"""Header authenticity checks.

These checks are heuristic and entirely offline. Authentication results are
*read from the email's own Authentication-Results header* - we do not perform
live SPF/DKIM/DMARC or DNS lookups, so a missing header is reported as
"not available" rather than "failed".
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

from core.brands import (
    ALLOWED_BRAND_DOMAINS,
    BRAND_DOMAINS,
    is_ip_address,
    is_suspicious_tld,
    registered_domain,
)
from core.email_parser import ParsedEmail, email_domain, parse_date
from core.models import Finding, Severity

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_MESSAGE_ID_DOMAIN_RE = re.compile(r"@([^>\s]+)>?$")

_SUSPICIOUS_MAILERS = ("phpmailer", "phpmail", "smtplib", "sendmail")


def _snippet(value: str, limit: int = 180) -> str:
    return " ".join((value or "").split())[:limit]


def analyze_headers(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    if not parsed.has_headers:
        findings.append(
            Finding(
                category="Header",
                title="No email headers supplied",
                detail=(
                    "Only the message body was analysed. Paste the full email "
                    "source (including From/Received headers) to enable header checks."
                ),
                severity=Severity.INFO,
            )
        )
        return findings

    from_domain = email_domain(parsed.sender_address)

    # ------------------------------------------------------------------
    # Required / expected headers
    # ------------------------------------------------------------------
    if not parsed.sender:
        findings.append(
            Finding(
                category="Header",
                title="Missing From header",
                detail="A legitimate email always identifies its sender.",
                severity=Severity.HIGH,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )
    if not parsed.subject:
        findings.append(
            Finding(
                category="Header",
                title="Missing Subject header",
                detail="Phishing emails sometimes use an empty subject to look harmless.",
                severity=Severity.LOW,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )
    if not parsed.date:
        findings.append(
            Finding(
                category="Header",
                title="Missing Date header",
                detail="The message has no send date, which is unusual for real mail.",
                severity=Severity.LOW,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )
    if not parsed.message_id:
        findings.append(
            Finding(
                category="Header",
                title="Missing Message-ID header",
                detail="Message-ID is normally added by the sending mail server.",
                severity=Severity.LOW,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )

    # ------------------------------------------------------------------
    # Sender identity / impersonation
    # ------------------------------------------------------------------
    if from_domain and is_ip_address(from_domain):
        findings.append(
            Finding(
                category="Header",
                title="Sender domain is an IP address",
                detail="Legitimate organisations send from named domains, not raw IPs.",
                severity=Severity.HIGH,
                evidence=from_domain,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )
    elif from_domain and "xn--" in from_domain:
        findings.append(
            Finding(
                category="Header",
                title="Punycode (internationalised) sender domain",
                detail=(
                    "Punycode can render as a lookalike of a well-known brand. "
                    "Inspect the address carefully."
                ),
                severity=Severity.HIGH,
                evidence=from_domain,
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )

    if from_domain and is_suspicious_tld(from_domain):
        findings.append(
            Finding(
                category="Header",
                title="Sender uses a high-abuse top-level domain",
                detail=f"The domain ends in .{from_domain.rsplit('.', 1)[-1]}, often used by phishers.",
                severity=Severity.LOW,
                evidence=from_domain,
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )

    display = parsed.sender_name.strip()
    if display:
        # "billing@paypal.com" shown as a display name, but sent from evil.com
        if "@" in display and "<" not in display:
            _, display_address = parseaddr(display)
            if display_address and display_address.lower() != parsed.sender_address:
                findings.append(
                    Finding(
                        category="Header",
                        title="Display name contains a different email address",
                        detail=(
                            "The visible name is an address that does not match the "
                            "real sender. This is a common spoofing trick."
                        ),
                        severity=Severity.HIGH,
                        evidence=_snippet(f"From: {parsed.sender}"),
                        mitre_id="T1656",
                        mitre_name="Impersonation",
                    )
                )

        lowered_display = display.lower()
        if registered_domain(from_domain) not in ALLOWED_BRAND_DOMAINS:
            for brand in BRAND_DOMAINS:
                if brand in lowered_display:
                    findings.append(
                        Finding(
                            category="Header",
                            title=f"Brand name in display name but not in domain ({brand})",
                            detail=(
                                "The sender advertises a trusted brand in the name "
                                "while the actual domain belongs to someone else."
                            ),
                            severity=Severity.HIGH,
                            evidence=_snippet(f"From: {parsed.sender}"),
                            mitre_id="T1656",
                            mitre_name="Impersonation",
                        )
                    )
                    break

    # ------------------------------------------------------------------
    # Reply-To / Return-Path alignment
    # ------------------------------------------------------------------
    reply_domain = email_domain(parsed.reply_to)
    if reply_domain and from_domain:
        if registered_domain(reply_domain) != registered_domain(from_domain):
            findings.append(
                Finding(
                    category="Header",
                    title="Reply-To points to a different domain",
                    detail=(
                        "Replies would go to a different organisation than the one "
                        "shown in From. This is a classic business-email-compromise "
                        "pattern."
                    ),
                    severity=Severity.HIGH,
                    evidence=_snippet(f"From: {parsed.sender} | Reply-To: {parsed.reply_to}"),
                    mitre_id="T1566",
                    mitre_name="Phishing: BEC",
                )
            )

    return_path_domain = email_domain(parsed.return_path)
    if return_path_domain and from_domain:
        if registered_domain(return_path_domain) != registered_domain(from_domain):
            findings.append(
                Finding(
                    category="Header",
                    title="Return-Path does not match the From domain",
                    detail=(
                        "The bounce address belongs to a different domain. Some "
                        "legitimate mailing services do this, but combined with other "
                        "signals it suggests spoofing."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=_snippet(
                        f"From: {parsed.sender} | Return-Path: {parsed.return_path}"
                    ),
                    mitre_id="T1566",
                    mitre_name="Phishing",
                )
            )

    # ------------------------------------------------------------------
    # Authentication results (SPF / DKIM / DMARC as reported by a gateway)
    # ------------------------------------------------------------------
    auth_results = _AUTH_RE.findall(parsed.auth_results)
    if auth_results:
        results: dict[str, str] = {}
        for mechanism, outcome in auth_results:
            results.setdefault(mechanism.lower(), outcome.lower())

        dmarc = results.get("dmarc")
        if dmarc in {"fail", "softfail"}:
            severity = Severity.HIGH
        elif dmarc == "none":
            severity = Severity.MEDIUM
        else:
            severity = None
        if severity:
            findings.append(
                Finding(
                    category="Header",
                    title=f"DMARC result: {dmarc}",
                    detail=(
                        "DMARC checks whether the sender is allowed to use the From "
                        "domain. A failing result is a strong spoofing signal."
                    ),
                    severity=severity,
                    evidence=_snippet(parsed.auth_results),
                    mitre_id="T1566",
                    mitre_name="Phishing: Domain Spoofing",
                )
            )

        spf = results.get("spf")
        if spf in {"fail", "softfail"}:
            findings.append(
                Finding(
                    category="Header",
                    title=f"SPF result: {spf}",
                    detail="The sending server is not authorised by the sender domain.",
                    severity=Severity.MEDIUM,
                    evidence=_snippet(parsed.auth_results),
                    mitre_id="T1566",
                    mitre_name="Phishing: Domain Spoofing",
                )
            )

        dkim = results.get("dkim")
        if dkim in {"fail", "temperror", "permerror"}:
            findings.append(
                Finding(
                    category="Header",
                    title=f"DKIM result: {dkim}",
                    detail="The message signature could not be verified.",
                    severity=Severity.MEDIUM,
                    evidence=_snippet(parsed.auth_results),
                    mitre_id="T1566",
                    mitre_name="Phishing: Domain Spoofing",
                )
            )

        if all(results.get(item) == "pass" for item in ("spf", "dkim", "dmarc")):
            findings.append(
                Finding(
                    category="Header",
                    title="SPF, DKIM and DMARC all passed",
                    detail="The reported authentication results do not show spoofing.",
                    severity=Severity.INFO,
                    evidence=_snippet(parsed.auth_results),
                )
            )
    else:
        findings.append(
            Finding(
                category="Header",
                title="No Authentication-Results header",
                detail=(
                    "SPF/DKIM/DMARC outcomes were not available in this message, so "
                    "sender authentication could not be assessed. This is common for "
                    "pasted emails but is still worth noting."
                ),
                severity=Severity.LOW,
            )
        )

    # ------------------------------------------------------------------
    # Routing / metadata
    # ------------------------------------------------------------------
    if len(parsed.received) > 6:
        findings.append(
            Finding(
                category="Header",
                title=f"Long Received chain ({len(parsed.received)} hops)",
                detail="Many hops can indicate relay abuse, though some providers add several.",
                severity=Severity.LOW,
            )
        )

    if any("localhost" in hop.lower() for hop in parsed.received[:2]):
        findings.append(
            Finding(
                category="Header",
                title="Received chain starts with localhost",
                detail="A local relay at the top of the chain is unusual for external mail.",
                severity=Severity.LOW,
            )
        )

    sent_at = parse_date(parsed.date)
    if parsed.date and sent_at is None:
        findings.append(
            Finding(
                category="Header",
                title="Unparseable Date header",
                detail="The send date is malformed, which legitimate mail servers avoid.",
                severity=Severity.LOW,
                evidence=_snippet(parsed.date),
            )
        )
    elif sent_at is not None:
        now = datetime.now(timezone.utc)
        if sent_at > now + timedelta(days=1):
            findings.append(
                Finding(
                    category="Header",
                    title="Date header is in the future",
                    detail="A send date in the future suggests a forged header.",
                    severity=Severity.MEDIUM,
                    evidence=_snippet(parsed.date),
                )
            )
        elif sent_at < now - timedelta(days=365):
            findings.append(
                Finding(
                    category="Header",
                    title="Date header is more than a year old",
                    detail="Old messages are sometimes replayed in phishing campaigns.",
                    severity=Severity.LOW,
                    evidence=_snippet(parsed.date),
                )
            )

    if parsed.message_id and from_domain:
        match = _MESSAGE_ID_DOMAIN_RE.search(parsed.message_id)
        if match:
            message_domain = match.group(1).strip(".")
            if registered_domain(message_domain) != registered_domain(from_domain):
                findings.append(
                    Finding(
                        category="Header",
                        title="Message-ID domain does not match the sender",
                        detail="The message identifier was generated for a different domain.",
                        severity=Severity.LOW,
                        evidence=_snippet(parsed.message_id),
                    )
                )

    mailer = (parsed.headers.get("x-mailer") or "").lower()
    if any(name in mailer for name in _SUSPICIOUS_MAILERS):
        findings.append(
            Finding(
                category="Header",
                title="Mail sent with a scripted mailer",
                detail="The X-Mailer header names a scripting library often used for bulk mail.",
                severity=Severity.LOW,
                evidence=_snippet(parsed.headers.get("x-mailer", "")),
                mitre_id="T1566",
                mitre_name="Phishing",
            )
        )

    return findings
