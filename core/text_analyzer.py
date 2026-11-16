"""Content and social-engineering analysis of the email body.

Everything here is rules-based and offline. Findings are grouped so a single
category cannot flood the report; scoring applies its own per-category cap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape

from core.brands import registered_domain
from core.email_parser import ParsedEmail
from core.models import Finding, Severity

_SCRIPT_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_BREAK_RE = re.compile(r"<\s*(br|/p|/div|/tr)\s*/?>", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"[ \t]+")
_ANCHOR_RE = re.compile(
    r"<a\b[^>]*?href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_DISPLAY_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.IGNORECASE
)


def html_to_text(html: str) -> str:
    """Strip tags/scripts and decode entities for keyword matching."""
    if not html:
        return ""
    without_scripts = _SCRIPT_RE.sub(" ", html)
    with_breaks = _BREAK_RE.sub("\n", without_scripts)
    text = _TAG_RE.sub(" ", with_breaks)
    return unescape(text)


@dataclass(frozen=True)
class Rule:
    title: str
    detail: str
    severity: Severity
    patterns: tuple[str, ...]
    mitre_id: str = "T1566"
    mitre_name: str = "Phishing"


# Kept as plain data so a beginner can read and extend the detection rules.
_RULES: tuple[Rule, ...] = (
    Rule(
        title="Asks the recipient to verify credentials",
        detail=(
            "The message pressures the reader to confirm an account, password or "
            "payment method. Real providers rarely ask for this by email."
        ),
        severity=Severity.HIGH,
        patterns=(
            r"\b(verify|confirm|update|validate|re-?activate|unlock|restore)\s+"
            r"(your\s+)?(account|identity|credentials|password|email|billing|payment)",
            r"\b(sign|log)\s?in\s+(to|into)\s+(your\s+)?"
            r"(account|online banking|portal|mailbox)",
            r"\benter\s+your\s+(password|credentials|username|pin)\b",
        ),
        mitre_id="T1598",
        mitre_name="Phishing for Information",
    ),
    Rule(
        title="Creates urgency",
        detail=(
            "Urgent deadlines are a core phishing tactic: they push the reader to "
            "act before checking the sender."
        ),
        severity=Severity.MEDIUM,
        patterns=(
            r"\burgent(ly)?\b",
            r"\bimmediately\b",
            r"\bwithin\s+\d+\s+(hours?|minutes?)\b",
            r"\bfinal\s+(warning|notice)\b",
            r"\bact\s+now\b",
            r"\b(account|access|profile|mailbox)\s+will\s+be\s+"
            r"(suspended|closed|deactivated|locked|terminated)\b",
            r"\blast\s+chance\b",
            r"\bexpir(e|es|ing)\s+(today|soon|within)\b",
        ),
        mitre_id="T1566",
        mitre_name="Phishing",
    ),
    Rule(
        title="Uses threats or consequences",
        detail=(
            "Threatening account loss or legal action is designed to create fear "
            "and bypass careful thinking."
        ),
        severity=Severity.MEDIUM,
        patterns=(
            r"\bunauthori[sz]ed\s+(login|access|activity|attempt)\b",
            r"\blegal\s+action\b",
            r"\bpermanently\s+(closed|deleted|suspended|blocked)\b",
            r"\bfailure\s+to\s+(comply|respond|verify|act)\b",
        ),
        mitre_id="T1566",
        mitre_name="Phishing",
    ),
    Rule(
        title="Payment or invoice change request",
        detail=(
            "Requests about wire transfers, bank-detail changes, gift cards or "
            "crypto are common in business-email-compromise fraud."
        ),
        severity=Severity.HIGH,
        patterns=(
            r"\bwire\s+transfer\b",
            r"\bbank\s+(account\s+)?details\b",
            r"\bchange\s+of\s+(bank|payment|remittance)\s+(details|information)\b",
            r"\bgift\s+cards?\b",
            r"\b(bitcoin|cryptocurrency|usdt|wallet\s+address)\b",
            r"\binvoice\s+(is\s+)?attached\b",
            r"\bpayment\s+(details|instructions|confirmation)\b",
            r"\bremittance\s+(advice|details)\b",
            r"\bpurchase\s+order\b",
        ),
        mitre_id="T1566",
        mitre_name="Phishing: BEC",
    ),
    Rule(
        title="Requests secrecy",
        detail=(
            "Asking the reader not to tell anyone is a strong fraud indicator and "
            "rare in legitimate business mail."
        ),
        severity=Severity.MEDIUM,
        patterns=(
            r"\bconfidential(ly)?\b",
            r"\bdo\s+not\s+(tell|inform|discuss|share)\b",
            r"\bkeep\s+this\s+(between|quiet|confidential)\b",
            r"\bhandle\s+with\s+discretion\b",
        ),
        mitre_id="T1566",
        mitre_name="Phishing",
    ),
    Rule(
        title="Generic greeting",
        detail=(
            "A generic salutation suggests the sender does not actually know the "
            "recipient. On its own this is weak evidence."
        ),
        severity=Severity.LOW,
        patterns=(
            r"\bdear\s+(customer|user|client|member|account\s+holder|"
            r"valued\s+customer|sir\s*/?\s*madam)\b",
        ),
        mitre_id="T1566",
        mitre_name="Phishing",
    ),
    Rule(
        title="Asks the reader to enable macros or editing",
        detail=(
            "Macro or 'enable editing' instructions are used to execute malicious "
            "code inside office documents."
        ),
        severity=Severity.HIGH,
        patterns=(
            r"\benable\s+(macros|editing|content|active\s+content)\b",
            r"\bclick\s+[\"']?enable\s+(editing|content)\b",
            r"\bif\s+(the\s+)?document\s+is\s+protected\b",
        ),
        mitre_id="T1204.002",
        mitre_name="User Execution: Malicious File",
    ),
)

_COMPILED_RULES: tuple[tuple[Rule, tuple[re.Pattern[str], ...]], ...] = tuple(
    (rule, tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule.patterns))
    for rule in _RULES
)

_EXCESSIVE_PUNCTUATION_RE = re.compile(r"[!?]{3,}")


def _evidence(text: str, start: int, end: int, radius: int = 45) -> str:
    snippet = text[max(0, start - radius) : min(len(text), end + radius)]
    return " ".join(snippet.split())[:180]


def _display_host(text: str) -> str:
    """If anchor text looks like a URL/domain, return its host."""
    candidate = unescape(text).strip().strip(".,;:()[]{}<>").rstrip("/")
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/")[0].split("?")[0].split("#")[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if candidate.lower().startswith("www."):
        candidate = candidate[4:]
    candidate = candidate.strip(".")
    if _DISPLAY_DOMAIN_RE.fullmatch(candidate):
        return candidate.lower()
    return ""


def _href_host(href: str) -> str:
    match = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", href.strip(), re.IGNORECASE)
    if not match:
        return ""
    host = match.group(1).rsplit("@", 1)[-1]
    host = host.split(":")[0].strip(".")
    return host.lower()


def _link_mismatches(html: str) -> list[Finding]:
    findings: list[Finding] = []
    if not html:
        return findings

    seen: set[tuple[str, str]] = set()
    for match in _ANCHOR_RE.finditer(html):
        href, inner = match.group(1), match.group(2)
        visible = html_to_text(inner)
        shown_host = _display_host(visible)
        real_host = _href_host(href)
        if not shown_host or not real_host:
            continue
        if registered_domain(shown_host) == registered_domain(real_host):
            continue
        key = (shown_host, real_host)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                category="Body",
                title="Link text hides the real destination",
                detail=(
                    "The visible link suggests one domain, but the button actually "
                    "points somewhere else."
                ),
                severity=Severity.HIGH,
                evidence=f"shown: {shown_host} | real: {real_host}",
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )
        if len(findings) >= 5:
            break
    return findings


def analyze_body(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    visible = html_to_text(parsed.body_html)
    combined = " ".join(
        part
        for part in (parsed.subject, parsed.body_text, visible)
        if part
    ).strip()

    if not combined:
        findings.append(
            Finding(
                category="Body",
                title="No message body",
                detail="The email has no readable text content.",
                severity=Severity.INFO,
            )
        )
        return findings

    for rule, patterns in _COMPILED_RULES:
        for pattern in patterns:
            match = pattern.search(combined)
            if match:
                findings.append(
                    Finding(
                        category="Body",
                        title=rule.title,
                        detail=rule.detail,
                        severity=rule.severity,
                        evidence=_evidence(combined, match.start(), match.end()),
                        mitre_id=rule.mitre_id,
                        mitre_name=rule.mitre_name,
                    )
                )
                break

    findings.extend(_link_mismatches(parsed.body_html))

    # Visual obfuscation heuristics -----------------------------------------
    letters = [character for character in visible if character.isalpha()]
    if len(letters) >= 80:
        uppercase_ratio = sum(character.isupper() for character in letters) / len(letters)
        if uppercase_ratio >= 0.4:
            findings.append(
                Finding(
                    category="Body",
                    title="Unusually high use of capital letters",
                    detail="SHOUTING text is often used to create alarm and urgency.",
                    severity=Severity.LOW,
                    evidence=f"{uppercase_ratio:.0%} of letters are uppercase",
                )
            )

    punctuation = _EXCESSIVE_PUNCTUATION_RE.search(combined)
    if punctuation:
        findings.append(
            Finding(
                category="Body",
                title="Excessive punctuation",
                detail="Repeated exclamation/question marks are a pressure tactic.",
                severity=Severity.LOW,
                evidence=_evidence(combined, punctuation.start(), punctuation.end()),
            )
        )

    return findings
