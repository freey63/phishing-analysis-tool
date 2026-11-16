"""Typed data structures shared by every module.

Keeping the shapes in one place means the analysers, the scoring engine, the
report builder, storage and the UI all speak the same language.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# How many points each finding contributes to the risk score.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}

SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

SEVERITY_RANK: dict[Severity, int] = {
    severity: index for index, severity in enumerate(SEVERITY_ORDER)
}

SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


RISK_LEVELS: list[RiskLevel] = [
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]

RISK_ICONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "🟢",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.HIGH: "🟠",
    RiskLevel.CRITICAL: "🔴",
}


class ReputationVerdict(str, Enum):
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    CLEAN = "Clean"
    UNKNOWN = "Unknown"  # deliberately distinct from Clean
    ERROR = "Error"  # lookup failed / rate limited


UNVERIFIED_VERDICTS = {ReputationVerdict.UNKNOWN, ReputationVerdict.ERROR}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _enum(enum_cls: type[Enum], value: Any, default: Enum) -> Any:
    """Coerce stored JSON strings back into enums, tolerating bad data."""
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Findings and indicators
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """One suspicious observation produced by an analyser."""

    category: str  # Header / Body / URL / Reputation / Attachment
    title: str
    detail: str
    severity: Severity = Severity.INFO
    evidence: str = ""
    mitre_id: str = ""
    mitre_name: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            category=str(data.get("category", "Other")),
            title=str(data.get("title", "")),
            detail=str(data.get("detail", "")),
            severity=_enum(Severity, data.get("severity"), Severity.INFO),
            evidence=str(data.get("evidence", "")),
            mitre_id=str(data.get("mitre_id", "")),
            mitre_name=str(data.get("mitre_name", "")),
        )


@dataclass
class IOC:
    """An indicator of compromise extracted from the email."""

    kind: str  # url / domain / ip / email
    value: str
    count: int = 1
    contexts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "count": self.count,
            "contexts": list(self.contexts),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IOC":
        return cls(
            kind=str(data.get("kind", "domain")),
            value=str(data.get("value", "")),
            count=int(data.get("count", 1) or 1),
            contexts=[str(item) for item in data.get("contexts", [])],
        )


@dataclass
class Reputation:
    """VirusTotal result for a single indicator."""

    ioc_kind: str
    value: str
    verdict: ReputationVerdict
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    detections: list[str] = field(default_factory=list)
    note: str = ""
    checked_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_kind": self.ioc_kind,
            "value": self.value,
            "verdict": self.verdict.value,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "total_engines": self.total_engines,
            "detections": list(self.detections),
            "note": self.note,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Reputation":
        return cls(
            ioc_kind=str(data.get("ioc_kind", "domain")),
            value=str(data.get("value", "")),
            verdict=_enum(
                ReputationVerdict, data.get("verdict"), ReputationVerdict.UNKNOWN
            ),
            malicious=int(data.get("malicious", 0) or 0),
            suspicious=int(data.get("suspicious", 0) or 0),
            harmless=int(data.get("harmless", 0) or 0),
            undetected=int(data.get("undetected", 0) or 0),
            total_engines=int(data.get("total_engines", 0) or 0),
            detections=[str(item) for item in data.get("detections", [])],
            note=str(data.get("note", "")),
            checked_at=str(data.get("checked_at", "")),
        )


@dataclass
class AttachmentInfo:
    """Metadata only - attachments are never opened or executed."""

    filename: str
    content_type: str = ""
    size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttachmentInfo":
        return cls(
            filename=str(data.get("filename", "")),
            content_type=str(data.get("content_type", "")),
            size_bytes=int(data.get("size_bytes", 0) or 0),
        )


# ---------------------------------------------------------------------------
# Risk and full result
# ---------------------------------------------------------------------------
@dataclass
class RiskAssessment:
    score: int = 0
    level: RiskLevel = RiskLevel.LOW
    breakdown: list[dict[str, Any]] = field(default_factory=list)
    unknown_reputation: bool = False
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "breakdown": [dict(item) for item in self.breakdown],
            "unknown_reputation": self.unknown_reputation,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RiskAssessment":
        return cls(
            score=int(data.get("score", 0) or 0),
            level=_enum(RiskLevel, data.get("level"), RiskLevel.LOW),
            breakdown=[dict(item) for item in data.get("breakdown", [])],
            unknown_reputation=bool(data.get("unknown_reputation", False)),
            summary=str(data.get("summary", "")),
        )


@dataclass
class AnalysisResult:
    """Everything produced by one analysis run."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=utc_now_iso)
    source: str = "Pasted email"
    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    reputations: list[Reputation] = field(default_factory=list)
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    ai_explanation: str = ""
    ai_used: bool = False
    ai_note: str = ""
    reputation_checked: bool = False
    message_info: dict[str, Any] = field(default_factory=dict)
    attachments: list[AttachmentInfo] = field(default_factory=list)

    # ---- convenience views ------------------------------------------------
    @property
    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: SEVERITY_RANK[item.severity])

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [item for item in self.findings if item.severity == severity]

    def iocs_of_kind(self, kind: str) -> list[IOC]:
        return [item for item in self.iocs if item.kind == kind]

    # ---- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "source": self.source,
            "subject": self.subject,
            "sender": self.sender,
            "recipients": list(self.recipients),
            "findings": [item.to_dict() for item in self.findings],
            "iocs": [item.to_dict() for item in self.iocs],
            "reputations": [item.to_dict() for item in self.reputations],
            "risk": self.risk.to_dict(),
            "ai_explanation": self.ai_explanation,
            "ai_used": self.ai_used,
            "ai_note": self.ai_note,
            "reputation_checked": self.reputation_checked,
            "message_info": dict(self.message_info),
            "attachments": [item.to_dict() for item in self.attachments],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        return cls(
            id=str(data.get("id", uuid.uuid4().hex[:12])),
            created_at=str(data.get("created_at", utc_now_iso())),
            source=str(data.get("source", "Pasted email")),
            subject=str(data.get("subject", "")),
            sender=str(data.get("sender", "")),
            recipients=[str(item) for item in data.get("recipients", [])],
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            iocs=[IOC.from_dict(item) for item in data.get("iocs", [])],
            reputations=[
                Reputation.from_dict(item) for item in data.get("reputations", [])
            ],
            risk=RiskAssessment.from_dict(data.get("risk", {})),
            ai_explanation=str(data.get("ai_explanation", "")),
            ai_used=bool(data.get("ai_used", False)),
            ai_note=str(data.get("ai_note", "")),
            reputation_checked=bool(data.get("reputation_checked", False)),
            message_info=dict(data.get("message_info", {})),
            attachments=[
                AttachmentInfo.from_dict(item)
                for item in data.get("attachments", [])
            ],
        )
