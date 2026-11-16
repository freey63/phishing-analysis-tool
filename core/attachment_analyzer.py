"""Attachment *metadata* checks.

We never open, decode, execute or preview an attachment. The analyser only
looks at the filename and declared MIME type, which is enough to raise useful
warnings and is completely safe.
"""

from __future__ import annotations

from pathlib import Path

from core.brands import (
    ARCHIVE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    MACRO_EXTENSIONS,
)
from core.models import AttachmentInfo, Finding, Severity


def _extensions(filename: str) -> list[str]:
    """Return every extension in a filename, e.g. invoice.pdf.exe -> [pdf, exe]."""
    parts = Path(filename.lower()).name.split(".")
    return [part for part in parts[1:] if part]


def analyze_attachments(attachments: list[AttachmentInfo]) -> list[Finding]:
    findings: list[Finding] = []

    for attachment in attachments:
        filename = attachment.filename or "(unnamed attachment)"
        extensions = _extensions(filename)
        if not extensions:
            continue

        primary = extensions[-1]

        if primary in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category="Attachment",
                    title=f"Executable/script attachment: {filename}",
                    detail=(
                        "This file type can run code or install software. "
                        "Never open it outside a sandbox."
                    ),
                    severity=Severity.HIGH,
                    evidence=filename,
                    mitre_id="T1566.001",
                    mitre_name="Spearphishing Attachment",
                )
            )

        elif primary in MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    category="Attachment",
                    title=f"Macro-capable document: {filename}",
                    detail=(
                        "Office documents can contain macros that run code when "
                        "'enable content' is clicked. Treat as untrusted."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=filename,
                    mitre_id="T1566.001",
                    mitre_name="Spearphishing Attachment",
                )
            )

        elif primary in ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    category="Attachment",
                    title=f"Archive attachment: {filename}",
                    detail=(
                        "Archives hide their real contents and are often used to "
                        "deliver executables or scripts."
                    ),
                    severity=Severity.LOW,
                    evidence=filename,
                    mitre_id="T1566.001",
                    mitre_name="Spearphishing Attachment",
                )
            )

        if len(extensions) >= 2:
            findings.append(
                Finding(
                    category="Attachment",
                    title=f"Double extension: {filename}",
                    detail=(
                        "A double extension is used to disguise an executable as "
                        "a document (for example invoice.pdf.exe)."
                    ),
                    severity=Severity.HIGH,
                    evidence=filename,
                    mitre_id="T1036.007",
                    mitre_name="Masquerading: Double File Extension",
                )
            )

        if attachment.size_bytes > 10 * 1024 * 1024:
            findings.append(
                Finding(
                    category="Attachment",
                    title=f"Large attachment: {filename}",
                    detail="Attachments over 10 MB are unusual for a normal email.",
                    severity=Severity.LOW,
                    evidence=f"{attachment.size_bytes / (1024 * 1024):.1f} MB",
                )
            )

    return findings
