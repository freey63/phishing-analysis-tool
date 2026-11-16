"""Built-in sample emails so the tool can be tested without real phish.

All samples are synthetic, use reserved documentation domains/IPs where
possible, and contain only defanged links.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import SAMPLES_DIR


@dataclass(frozen=True)
class SampleEmail:
    key: str
    title: str
    description: str
    expected: str
    filename: str

    @property
    def path(self):
        return SAMPLES_DIR / self.filename


_SAMPLES: tuple[SampleEmail, ...] = (
    SampleEmail(
        key="credential_phish",
        title="Credential phish (lookalike domain)",
        description=(
            "Fake Microsoft 365 alert using a typosquatted domain, failed DMARC, "
            "a mismatched Reply-To and hidden link text."
        ),
        expected="Critical",
        filename="01-credential-phish.eml",
    ),
    SampleEmail(
        key="bec_invoice",
        title="CEO fraud / invoice change (BEC)",
        description=(
            "Boardroom-pressure email asking finance to change bank details and "
            "keep the request secret, with a free-mail Reply-To."
        ),
        expected="High",
        filename="02-bec-invoice.txt",
    ),
    SampleEmail(
        key="malware_lure",
        title="Malware delivery lure",
        description=(
            "Parcel-themed email with a shortened link, macro-enabled .docm "
            "attachment and failed authentication."
        ),
        expected="Critical",
        filename="03-malware-lure.eml",
    ),
    SampleEmail(
        key="legitimate",
        title="Legitimate newsletter (control)",
        description=(
            "A clean newsletter with aligned From/Return-Path, passing SPF, DKIM "
            "and DMARC, and ordinary links. Should score Low."
        ),
        expected="Low",
        filename="04-legitimate-newsletter.eml",
    ),
)


def list_samples() -> list[SampleEmail]:
    return [sample for sample in _SAMPLES if sample.path.exists()]


def get_sample(key: str) -> SampleEmail:
    for sample in _SAMPLES:
        if sample.key == key:
            return sample
    raise KeyError(f"Unknown sample: {key}")


def load_sample_text(key: str) -> str:
    return get_sample(key).path.read_text(encoding="utf-8", errors="replace")
