"""Extract indicators of compromise (IOCs) from email text.

Supports common "defanged" notation used by security teams, e.g.
``hxxps://bad[.]example[.]com`` or ``user[at]example[.]com``.

Only strings are produced - nothing is fetched or resolved.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from core.brands import is_file_like_domain
from core.models import IOC

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`\)\]\}]+")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)

_DEFANG_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)", re.IGNORECASE), ":"),
    (re.compile(r"\[at\]|\(at\)|\{at\}", re.IGNORECASE), "@"),
    (re.compile(r"\[/\]|\(/\)", re.IGNORECASE), "/"),
)

_MAX_PER_KIND = 100
_WHITESPACE_RE = re.compile(r"\s+")
_TRAILING_URL_CHARS = ".,;:!?'\")]}>"


def refang(text: str) -> str:
    """Undo defanging so the extractors see normal indicators."""
    result = text or ""
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result


def defang(value: str) -> str:
    """Make an indicator safe to display (not clickable)."""
    if not value:
        return ""
    result = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    result = result.replace(".", "[.]").replace("@", "[at]")
    return result


def _normalise_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.hostname:
        return url
    netloc = parts.netloc.lower()
    return urlunsplit(
        (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
    )


def _context(text: str, needle: str, radius: int = 45) -> str:
    index = text.lower().find(needle.lower())
    if index < 0:
        return ""
    snippet = text[max(0, index - radius) : index + len(needle) + radius]
    return _WHITESPACE_RE.sub(" ", snippet).strip()[:180]


def _add(
    bucket: dict[tuple[str, str], IOC],
    kind: str,
    value: str,
    normalized_text: str,
    original_text: str,
) -> None:
    value = value.strip()
    if not value:
        return
    key = (kind, value.lower())
    if key in bucket:
        bucket[key].count += 1
        return
    context = _context(original_text, value) or _context(normalized_text, value)
    bucket[key] = IOC(
        kind=kind,
        value=value,
        count=1,
        contexts=[context] if context else [],
    )


def extract_iocs(text: str) -> list[IOC]:
    """Return de-duplicated URLs, domains, IPs and email addresses."""
    if not text:
        return []

    normalized = refang(text)
    bucket: dict[tuple[str, str], IOC] = {}
    url_hosts: set[str] = set()

    # URLs ------------------------------------------------------------------
    url_count = 0
    for match in URL_RE.finditer(normalized):
        url = match.group(0).rstrip(_TRAILING_URL_CHARS)
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").strip().lower()
        except ValueError:
            continue
        if not host:
            continue
        _add(bucket, "url", _normalise_url(url), normalized, text)
        url_hosts.add(host)
        url_count += 1
        if url_count >= _MAX_PER_KIND:
            break

    # Email addresses -------------------------------------------------------
    email_count = 0
    for match in EMAIL_RE.finditer(normalized):
        address = match.group(0).rstrip(".,;:").lower()
        _add(bucket, "email", address, normalized, text)
        email_count += 1
        if email_count >= _MAX_PER_KIND:
            break

    # IP addresses ----------------------------------------------------------
    ip_count = 0
    for match in IPV4_RE.finditer(normalized):
        raw_ip = match.group(0)
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        _add(bucket, "ip", str(address), normalized, text)
        ip_count += 1
        if ip_count >= _MAX_PER_KIND:
            break

    # Domains ---------------------------------------------------------------
    domain_count = 0
    for match in DOMAIN_RE.finditer(normalized):
        domain = match.group(0).rstrip(".").lower()
        if len(domain) > 253 or is_file_like_domain(domain):
            continue
        if domain in {"localhost", "localhost.localdomain"}:
            continue
        if domain.rsplit(".", 1)[-1].isdigit():
            continue
        _add(bucket, "domain", domain, normalized, text)
        domain_count += 1
        if domain_count >= _MAX_PER_KIND:
            break

    # Order: URLs, domains, IPs, emails (most useful for an analyst first).
    order = {"url": 0, "domain": 1, "ip": 2, "email": 3}
    return sorted(bucket.values(), key=lambda item: (order[item.kind], item.value))
