"""Reusable Streamlit widgets and DataFrame builders."""

from __future__ import annotations

import html
from datetime import datetime

import pandas as pd
import streamlit as st

from core.ioc_extractor import defang
from core.models import (
    AnalysisResult,
    Finding,
    IOC,
    RISK_ICONS,
    Reputation,
    ReputationVerdict,
    RiskAssessment,
    SEVERITY_ICONS,
    SEVERITY_ORDER,
    Severity,
)

SEVERITY_COLORS = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

RISK_COLORS = {
    "Low": "#15803d",
    "Medium": "#a16207",
    "High": "#c2410c",
    "Critical": "#b91c1c",
}

VERDICT_LABELS = {
    ReputationVerdict.MALICIOUS: "🔴 Malicious",
    ReputationVerdict.SUSPICIOUS: "🟠 Suspicious",
    ReputationVerdict.CLEAN: "🟢 Clean",
    ReputationVerdict.UNKNOWN: "⚪ Unknown",
    ReputationVerdict.ERROR: "⚠️ Error",
}


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .risk-badge {
            display: inline-block;
            padding: 0.45rem 1.1rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 1.05rem;
            color: #ffffff;
            margin-bottom: 0.35rem;
        }
        .finding-card {
            border-left: 4px solid #6b7280;
            background: rgba(127, 127, 127, 0.08);
            border-radius: 0.45rem;
            padding: 0.65rem 0.9rem;
            margin-bottom: 0.55rem;
        }
        .finding-title {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 0.25rem;
        }
        .sev-pill {
            color: #ffffff;
            font-size: 0.68rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 0.1rem 0.45rem;
            border-radius: 999px;
        }
        .mitre-pill {
            background: #1e293b;
            color: #38bdf8;
            border: 1px solid #0284c7;
            font-size: 0.68rem;
            font-weight: 600;
            padding: 0.1rem 0.45rem;
            border-radius: 4px;
        }
        .finding-detail {
            font-size: 0.9rem;
            opacity: 0.92;
            margin-bottom: 0.2rem;
        }
        .finding-evidence {
            font-size: 0.8rem;
            opacity: 0.75;
            word-break: break-word;
        }
        .muted {
            font-size: 0.82rem;
            opacity: 0.75;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def risk_badge(level, score: int) -> str:
    color = RISK_COLORS.get(level.value, "#6b7280")
    icon = RISK_ICONS.get(level, "⚪")
    return (
        f'<span class="risk-badge" style="background:{color}">'
        f"{icon} {level.value} risk · {score}/100</span>"
    )


def finding_card(finding: Finding) -> str:
    color = SEVERITY_COLORS.get(finding.severity, "#6b7280")
    icon = SEVERITY_ICONS.get(finding.severity, "⚪")
    evidence = ""
    if finding.evidence:
        evidence = (
            '<div class="finding-evidence">Evidence: <code>'
            f"{html.escape(finding.evidence)}</code></div>"
        )
    mitre_badge = ""
    if getattr(finding, "mitre_id", ""):
        m_title = html.escape(getattr(finding, "mitre_name", "") or "ATT&CK Technique")
        mitre_badge = (
            f'<span class="mitre-pill" title="{m_title}">'
            f"MITRE {html.escape(finding.mitre_id)}</span>"
        )
    return (
        f'<div class="finding-card" style="border-left-color:{color}">'
        '<div class="finding-title">'
        f"{icon} <strong>{html.escape(finding.title)}</strong>"
        f'<span class="sev-pill" style="background:{color}">'
        f"{finding.severity.value}</span>"
        f"{mitre_badge}</div>"
        f'<div class="finding-detail">{html.escape(finding.detail)}</div>'
        f"{evidence}</div>"
    )


def format_timestamp(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return value or "unknown"


def iocs_dataframe(iocs: list[IOC]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Type": ioc.kind.upper(),
                "Indicator (defanged)": defang(ioc.value),
                "Occurrences": ioc.count,
                "Context": (ioc.contexts[0] if ioc.contexts else "")[:140],
            }
            for ioc in iocs
        ],
        columns=["Type", "Indicator (defanged)", "Occurrences", "Context"],
    )


def reputations_dataframe(reputations: list[Reputation]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Type": item.ioc_kind.upper(),
                "Indicator (defanged)": defang(item.value),
                "Verdict": VERDICT_LABELS.get(item.verdict, item.verdict.value),
                "Flagged": (
                    f"{item.malicious + item.suspicious}/{item.total_engines}"
                    if item.total_engines
                    else "—"
                ),
                "Note": item.note,
            }
            for item in reputations
        ],
        columns=["Type", "Indicator (defanged)", "Verdict", "Flagged", "Note"],
    )


def risk_breakdown_dataframe(risk: RiskAssessment) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Category": item["category"],
                "Points": item["points"],
                "Cap": item["max_points"],
                "Findings": item["findings"],
            }
            for item in risk.breakdown
        ],
        columns=["Category", "Points", "Cap", "Findings"],
    )


def message_details_dataframe(result: AnalysisResult) -> pd.DataFrame:
    info = result.message_info
    rows = [
        ("Subject", result.subject or "(no subject)"),
        ("From", result.sender or "(unknown)"),
        ("Reply-To", info.get("reply_to", "—")),
        ("Return-Path", info.get("return_path", "—")),
        ("Date", info.get("date", "—")),
        ("Message-ID", info.get("message_id", "—")),
        ("Received hops", info.get("received_hops", "—")),
        ("Authentication", info.get("authentication_results", "—")),
        ("HTML body", "Yes" if info.get("has_html_body") else "No"),
        ("Attachments", info.get("attachment_count", 0)),
    ]
    # Force every value to text so Arrow never sees mixed int/str columns.
    return pd.DataFrame(
        [(field, str(value)) for field, value in rows], columns=["Field", "Value"]
    )


def findings_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    order = ["Header", "Body", "URL", "Reputation", "Attachment", "Other"]
    grouped: dict[str, list[Finding]] = {}
    for category in order:
        group = [item for item in findings if item.category == category]
        if group:
            grouped[category] = sorted(
                group, key=lambda item: SEVERITY_ORDER.index(item.severity)
            )
    return grouped
