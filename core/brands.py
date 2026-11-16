"""Brand lists and domain helpers used for impersonation detection.

All lookups are offline: ``tldextract`` is explicitly configured with no
suffix-list URLs so it uses the snapshot bundled with the package.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import tldextract

# Disable network fetching: offline-first and deterministic.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# Brand -> official registrable domains. Used to decide whether a domain is
# impersonating a brand or legitimately belongs to it.
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "live.com",
        "outlook.com",
        "microsoftstore.com",
    },
    "apple": {"apple.com", "icloud.com"},
    "google": {
        "google.com",
        "google.co.uk",
        "google.de",
        "gmail.com",
        "youtube.com",
        "googleusercontent.com",
    },
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "hsbc": {"hsbc.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "spotify": {"spotify.com"},
    "github": {"github.com", "githubusercontent.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

ALLOWED_BRAND_DOMAINS: frozenset[str] = frozenset(
    domain for domains in BRAND_DOMAINS.values() for domain in domains
)

# Short labels that are one edit away from a brand but are ordinary words.
# Prevents obvious false positives like apply.com vs apple.com.
_TYPOSQUAT_IGNORE = frozenset(
    {
        "apply",
        "appleid",
        "googl",
        "micro",
        "soft",
        "amaz",
        "netfl",
        "linked",
        "adob",
        "chase",
        "steam",
    }
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "zip",
        "mov",
        "top",
        "xyz",
        "click",
        "country",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "work",
        "rest",
        "cam",
        "icu",
        "buzz",
        "loan",
        "surf",
        "bar",
        "review",
        "kim",
        "accountant",
        "science",
        "party",
        "gdn",
        "men",
        "date",
        "stream",
        "download",
        "racing",
        "win",
        "bid",
        "trade",
        "webcam",
        "vip",
        "cyou",
    }
)

SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "rebrand.ly",
        "s.id",
        "lnkd.in",
        "t.ly",
        "v.gd",
        "tiny.cc",
        "clck.ru",
        "shrtco.de",
    }
)

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "scr",
        "com",
        "pif",
        "bat",
        "cmd",
        "js",
        "jse",
        "vbs",
        "vbe",
        "hta",
        "jar",
        "lnk",
        "iso",
        "img",
        "msi",
        "ps1",
        "ace",
        "arj",
        "cab",
        "reg",
        "wsf",
    }
)

MACRO_EXTENSIONS: frozenset[str] = frozenset(
    {"docm", "xlsm", "pptm", "dotm", "xlam", "xltm", "doc", "xls", "ppt"}
)

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "img"}
)

# Extensions that are almost certainly part of a filename, not a real TLD.
_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "svg",
        "ico",
        "css",
        "js",
        "json",
        "xml",
        "php",
        "html",
        "htm",
        "txt",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "zip",
        "rar",
        "exe",
        "mp3",
        "mp4",
        "woff",
        "woff2",
        "ttf",
    }
)


# ---------------------------------------------------------------------------
# Basic host helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """Return ``(subdomain, domain, suffix)`` for a hostname, offline."""
    cleaned = (host or "").strip().lower().strip(".").split(":")[0]
    extracted = _TLD_EXTRACTOR(cleaned)
    return extracted.subdomain, extracted.domain, extracted.suffix


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """Return the registrable domain (``a.b.example.co.uk`` -> ``example.co.uk``)."""
    subdomain, domain, suffix = split_host(host)
    if not domain or not suffix:
        return (host or "").strip().lower().strip(".")
    return f"{domain}.{suffix}"


def public_suffix(host: str) -> str:
    return split_host(host)[2]


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(host: str) -> bool:
    """True for a global unicast IP (safe to look up on VirusTotal)."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_reserved
        or address.is_multicast
        or address.is_link_local
    )


def is_file_like_domain(candidate: str) -> bool:
    suffix = candidate.rsplit(".", 1)[-1].lower() if "." in candidate else ""
    return suffix in _FILE_EXTENSIONS


def is_suspicious_tld(host: str) -> bool:
    return public_suffix(host) in SUSPICIOUS_TLDS


# ---------------------------------------------------------------------------
# Impersonation detection
# ---------------------------------------------------------------------------
def _host_tokens(host: str) -> list[str]:
    subdomain, domain, _ = split_host(host)
    raw = f"{subdomain}.{domain}".strip(".")
    return [token for token in re.split(r"[.\-_]", raw) if token]


def spoofed_brand(host: str) -> str | None:
    """Return a brand name if the host uses it but is not an official domain."""
    registrable = registered_domain(host)
    if registrable in ALLOWED_BRAND_DOMAINS:
        return None
    tokens = set(_host_tokens(host))
    for brand in BRAND_DOMAINS:
        if brand in tokens:
            return brand
    return None


def levenshtein(left: str, right: str) -> int:
    """Small iterative edit-distance implementation (no extra dependencies)."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (left_char != right_char)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def typosquat_brand(host: str) -> str | None:
    """Detect a brand name misspelled by one or two characters."""
    if is_ip_address(host):
        return None
    registrable = registered_domain(host)
    if registrable in ALLOWED_BRAND_DOMAINS:
        return None
    _, domain, suffix = split_host(host)
    label = (domain or "").lower()
    if not label or not suffix or label in _TYPOSQUAT_IGNORE:
        return None
    for brand in BRAND_DOMAINS:
        if len(brand) < 5:
            continue
        allowed_distance = 1 if len(brand) < 8 else 2
        distance = levenshtein(label, brand)
        if 0 < distance <= allowed_distance:
            return brand
    return None
