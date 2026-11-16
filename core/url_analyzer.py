"""Static URL and domain analysis.

Nothing in this module makes a network request. URLs are parsed as text and
checked against heuristics: IP hosts, punycode, brand impersonation, URL
shorteners, dangerous file extensions, encoded separators and so on.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from core.brands import (
    DANGEROUS_EXTENSIONS,
    SHORTENER_DOMAINS,
    is_ip_address,
    is_suspicious_tld,
    registered_domain,
    spoofed_brand,
    split_host,
    typosquat_brand,
)
from core.models import Finding, IOC, Severity

_HEX_OR_DECIMAL_IP_RE = re.compile(r"^(?:0x[0-9a-f]+|\d{8,10})$", re.IGNORECASE)
_REDIRECT_PARAM_RE = re.compile(
    r"(?:^|[?&])(url|redirect|redirect_uri|next|target|dest|destination)=",
    re.IGNORECASE,
)


def _snippet(value: str, limit: int = 140) -> str:
    return (value or "")[:limit]


def _host_findings(host: str) -> list[Finding]:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return []

    findings: list[Finding] = []

    if is_ip_address(host):
        findings.append(
            Finding(
                category="URL",
                title="Link uses a raw IP address",
                detail=(
                    "Legitimate services use domain names. A raw IP hides who owns "
                    "the destination and bypasses domain reputation."
                ),
                severity=Severity.HIGH,
                evidence=_snippet(host),
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )
        return findings

    if _HEX_OR_DECIMAL_IP_RE.fullmatch(host):
        findings.append(
            Finding(
                category="URL",
                title="Link uses an encoded IP address",
                detail="Decimal/hex IP notation is used to disguise the real destination.",
                severity=Severity.HIGH,
                evidence=_snippet(host),
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )
        return findings

    if "xn--" in host:
        findings.append(
            Finding(
                category="URL",
                title="Punycode hostname",
                detail=(
                    "Internationalised characters can make a fake domain look "
                    "identical to a real brand."
                ),
                severity=Severity.HIGH,
                evidence=_snippet(host),
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )

    brand = spoofed_brand(host)
    if brand:
        findings.append(
            Finding(
                category="URL",
                title=f"Possible {brand} impersonation",
                detail=(
                    f"The domain contains the brand '{brand}' but is not an official "
                    f"{brand} domain. Check the registrable domain, not the prefix."
                ),
                severity=Severity.HIGH,
                evidence=_snippet(host),
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )
    else:
        lookalike = typosquat_brand(host)
        if lookalike:
            findings.append(
                Finding(
                    category="URL",
                    title=f"Lookalike domain for {lookalike}",
                    detail=(
                        "The domain is a small misspelling of a well-known brand "
                        "(typosquatting)."
                    ),
                    severity=Severity.HIGH,
                    evidence=_snippet(host),
                    mitre_id="T1566.002",
                    mitre_name="Spearphishing Link",
                )
            )

    if is_suspicious_tld(host):
        findings.append(
            Finding(
                category="URL",
                title="High-abuse top-level domain",
                detail="This TLD is frequently used for short-lived phishing sites.",
                severity=Severity.LOW,
                evidence=_snippet(host),
                mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
            )
        )

    if host in SHORTENER_DOMAINS:
        findings.append(
            Finding(
                category="URL",
                title="URL shortener hides the destination",
                detail=(
                    "The real destination is only revealed after clicking. We never "
                    "open it; expand it in a sandbox instead."
                ),
                severity=Severity.MEDIUM,
                evidence=_snippet(host),
                mitre_id="T1566.003",
                mitre_name="Spearphishing via Service",
            )
        )

    _, domain, suffix = split_host(host)
    if domain and suffix:
        subdomain_count = len(host.split(".")) - len(f"{domain}.{suffix}".split("."))
        if subdomain_count >= 4:
            findings.append(
                Finding(
                    category="URL",
                    title="Excessive number of subdomains",
                    detail=(
                        "Long subdomain chains are used to push the real domain out "
                        "of sight on mobile screens."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=_snippet(host),
                )
            )

        if domain.count("-") >= 3:
            findings.append(
                Finding(
                    category="URL",
                    title="Many hyphens in the domain",
                    detail="Hyphen-stuffed domains are common in impersonation campaigns.",
                    severity=Severity.LOW,
                    evidence=_snippet(host),
                )
            )

    if len(host) > 50:
        findings.append(
            Finding(
                category="URL",
                title="Unusually long hostname",
                detail="Long hostnames are harder to read and often disguise the real domain.",
                severity=Severity.LOW,
                evidence=_snippet(host),
            )
        )

    return findings


def _url_findings(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return findings

    if parts.scheme.lower() == "http":
        findings.append(
            Finding(
                category="URL",
                title="Link uses unencrypted HTTP",
                detail="Credentials or data would travel without TLS protection.",
                severity=Severity.LOW,
                evidence=_snippet(url),
            )
        )

    if parts.username or parts.password:
        findings.append(
            Finding(
                category="URL",
                title="URL contains embedded credentials",
                detail=(
                    "Text before '@' can make a URL look like it belongs to another "
                    "site. The real host comes after '@'."
                ),
                severity=Severity.HIGH,
                evidence=_snippet(url),
            )
        )

    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and port not in (80, 443):
        findings.append(
            Finding(
                category="URL",
                title=f"Non-standard port ({port})",
                detail="Unusual ports often indicate ad-hoc or compromised infrastructure.",
                severity=Severity.MEDIUM,
                evidence=_snippet(url),
            )
        )

    path = unquote(parts.path or "")
    segments = [segment for segment in path.split("/") if segment]
    if segments:
        last_segment = segments[-1].lower()
        extension = last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""
        if extension in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category="URL",
                    title=f"Link points to an executable/script (.{extension})",
                    detail="Downloading and running this file could compromise the machine.",
                    severity=Severity.HIGH,
                    evidence=_snippet(url),
                    mitre_id="T1566.001",
                    mitre_name="Spearphishing Attachment",
                )
            )
        # invoice.pdf.exe style double extension
        if last_segment.count(".") >= 2:
            pieces = last_segment.split(".")
            if pieces[-1] in DANGEROUS_EXTENSIONS and pieces[-2] in {
                "pdf",
                "doc",
                "docx",
                "xls",
                "xlsx",
                "jpg",
                "png",
                "txt",
            }:
                findings.append(
                    Finding(
                        category="URL",
                        title="Double file extension in link",
                        detail="The filename disguises an executable as a document.",
                        severity=Severity.HIGH,
                        evidence=_snippet(url),
                        mitre_id="T1036.007",
                        mitre_name="Masquerading: Double File Extension",
                    )
                )

    if "%00" in url.lower():
        findings.append(
            Finding(
                category="URL",
                title="Null byte in URL",
                detail="Encoded null bytes can bypass naive file-type checks.",
                severity=Severity.HIGH,
                evidence=_snippet(url),
            )
        )
    elif url.count("%") >= 6:
        findings.append(
            Finding(
                category="URL",
                title="Heavily encoded URL",
                detail="Heavy percent-encoding is often used to obfuscate the destination.",
                severity=Severity.LOW,
                evidence=_snippet(url),
            )
        )

    if len(parts.query or "") > 120:
        findings.append(
            Finding(
                category="URL",
                title="Very long query string",
                detail="Long queries can carry tracking identifiers or hide redirects.",
                severity=Severity.LOW,
                evidence=_snippet(url),
            )
        )

    if _REDIRECT_PARAM_RE.search(parts.query or ""):
        findings.append(
            Finding(
                category="URL",
                title="URL contains a redirect parameter",
                detail="The final destination may differ from the visible domain.",
                severity=Severity.LOW,
                evidence=_snippet(url),
            )
        )

    return findings


def analyze_iocs(iocs: list[IOC]) -> list[Finding]:
    """Analyse URL and domain IOCs, de-duplicating repeated host checks."""
    findings: list[Finding] = []
    seen_hosts: set[str] = set()
    seen_keys: set[tuple[str, str]] = set()

    for ioc in iocs:
        if ioc.kind == "url":
            try:
                host = (urlsplit(ioc.value).hostname or "").lower()
            except ValueError:
                host = ""
            if host and host not in seen_hosts:
                findings.extend(_host_findings(host))
                seen_hosts.add(host)
            findings.extend(_url_findings(ioc.value))

    for ioc in iocs:
        if ioc.kind != "domain":
            continue
        host = ioc.value.lower().strip(".")
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        findings.extend(_host_findings(host))

    # De-duplicate identical title/evidence pairs (e.g. several URLs on one host).
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.title, finding.evidence)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(finding)

    return unique
