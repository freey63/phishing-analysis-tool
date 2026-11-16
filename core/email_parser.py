"""Turn raw email text (pasted or .eml) into a predictable structure.

Uses only the Python standard library. MIME parts are decoded as text; any
part marked as an attachment is recorded by name/type/size and then ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from core.models import AttachmentInfo

# Enough to recognise real headers without mistaking a body sentence like
# "Subject: hello" in the middle of a paragraph.
_HEADER_RE = re.compile(
    r"^(from|to|cc|subject|date|received|reply-to|return-path|message-id|"
    r"authentication-results|mime-version|content-type|x-mailer|dkim-signature)"
    r"\s*:",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class ParsedEmail:
    """Normalised view of one email message."""

    raw: str
    has_headers: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    header_values: dict[str, list[str]] = field(default_factory=dict)
    subject: str = ""
    sender: str = ""
    sender_name: str = ""
    sender_address: str = ""
    recipients: list[str] = field(default_factory=list)
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    date: str = ""
    received: list[str] = field(default_factory=list)
    auth_results: str = ""
    body_text: str = ""
    body_html: str = ""
    attachments: list[AttachmentInfo] = field(default_factory=list)

    @property
    def combined_body(self) -> str:
        parts = [part for part in (self.body_text, self.body_html) if part]
        return "\n\n".join(parts)


def email_domain(value: str) -> str:
    """Extract the domain from ``Name <user@example.com>`` safely."""
    if not value:
        return ""
    _, address = parseaddr(value)
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[1].strip().strip(">").strip(".").lower()
    return domain


def parse_date(value: str) -> datetime | None:
    """Parse an RFC-2822 date into a timezone-aware datetime, or None."""
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _decode_part(part) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return content or ""
    except Exception:  # noqa: BLE001 - malformed MIME is common in real phish
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("utf-8", errors="replace")


def parse_email(raw: str, source: str = "Pasted email") -> ParsedEmail:
    """Parse raw text. If no headers are present, treat it as body-only."""
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    has_headers = bool(_HEADER_RE.search(text[:20000]))

    if not has_headers:
        looks_html = bool(re.search(r"<(html|body|a|div|p)\b", text, re.IGNORECASE))
        return ParsedEmail(
            raw=text,
            has_headers=False,
            body_text=text,
            body_html=text if looks_html else "",
        )

    message = Parser(policy=policy.default).parsestr(text)

    header_values: dict[str, list[str]] = {}
    for key, value in message.items():
        header_values.setdefault(key.lower(), []).append(str(value))
    headers = {key: values[0] for key, values in header_values.items()}

    sender_raw = str(message.get("From", "")).strip()
    sender_name, sender_address = parseaddr(sender_raw)
    recipients = [
        address
        for _, address in getaddresses(
            [
                str(message.get("To", "")),
                str(message.get("Cc", "")),
            ]
        )
        if address
    ]

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            if isinstance(payload, str):
                payload = payload.encode("utf-8", errors="replace")
            attachments.append(
                AttachmentInfo(
                    filename=filename or "(unnamed attachment)",
                    content_type=part.get_content_type(),
                    size_bytes=len(payload),
                )
            )
            continue

        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        content = _decode_part(part)
        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    return ParsedEmail(
        raw=text,
        has_headers=True,
        headers=headers,
        header_values=header_values,
        subject=str(message.get("Subject", "")).strip(),
        sender=sender_raw,
        sender_name=str(sender_name or "").strip(),
        sender_address=str(sender_address or "").strip().lower(),
        recipients=recipients,
        reply_to=str(message.get("Reply-To", "")).strip(),
        return_path=str(message.get("Return-Path", "")).strip(),
        message_id=str(message.get("Message-ID", "")).strip(),
        date=str(message.get("Date", "")).strip(),
        received=[str(item) for item in (message.get_all("Received") or [])],
        auth_results=" | ".join(
            str(item) for item in (message.get_all("Authentication-Results") or [])
        ),
        body_text="\n\n".join(part.strip() for part in plain_parts if part.strip()),
        body_html="\n".join(html_parts).strip(),
        attachments=attachments,
    )
