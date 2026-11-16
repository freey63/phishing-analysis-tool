"""Build human-readable Markdown and machine-readable JSON reports.

Reports never contain API keys or the raw email body. URL IOCs are defanged
(``hxxps://evil[.]example``) so a reader cannot accidentally click them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from config import APP_NAME, APP_VERSION
from core.ioc_extractor import defang
from core.models import (
    AnalysisResult,
    RISK_ICONS,
    SEVERITY_ICONS,
    SEVERITY_ORDER,
    ReputationVerdict,
)

_SAFE_FILENAME_RE = re.compile(r"[^a-z0-9]+")


def _cell(value: object) -> str:
    """Make a value safe inside a Markdown table cell."""
    text = " ".join(str(value).split())
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|")[:400]


def _code(value: str) -> str:
    """Render evidence as an inert code span."""
    text = " ".join(str(value).split()).replace("`", "'")[:300]
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return "`" + text + "`"


def _format_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return value or "unknown"


def report_filename(result: AnalysisResult) -> str:
    stamp = _format_time(result.created_at).replace(":", "").replace(" ", "_")
    subject = _SAFE_FILENAME_RE.sub("-", result.subject.lower()).strip("-")[:40]
    return f"phishing-report-{stamp}{'-' + subject if subject else ''}.md"


def json_filename(result: AnalysisResult) -> str:
    return report_filename(result).replace(".md", ".json")


def _reputation_label(item: ReputationVerdict) -> str:
    return {
        ReputationVerdict.MALICIOUS: "🔴 Malicious",
        ReputationVerdict.SUSPICIOUS: "🟠 Suspicious",
        ReputationVerdict.CLEAN: "🟢 Clean",
        ReputationVerdict.UNKNOWN: "⚪ Unknown / not verified",
        ReputationVerdict.ERROR: "⚠️ Lookup error",
    }.get(item, item.value)


def _recommended_actions(result: AnalysisResult) -> list[str]:
    actions = [
        "Do not click links, open attachments, or reply to the sender.",
        "Verify the sender through a separate, known channel before acting.",
    ]
    if result.risk.level.value in {"High", "Critical"}:
        actions.extend(
            [
                "Report the message to your security team and preserve the original headers.",
                "Block the listed domains/IPs at the mail gateway, proxy and DNS layer.",
                "Search other mailboxes for the same subject, sender or indicators.",
            ]
        )
    if any(
        finding.title.startswith("Asks the recipient to verify")
        for finding in result.findings
    ):
        actions.append(
            "If credentials were entered, reset the password and revoke active sessions immediately."
        )
    actions.append(
        "Treat 'unknown' reputation as unverified, not safe. Analyse links in an isolated sandbox."
    )
    return actions


def build_markdown(result: AnalysisResult) -> str:
    """Create a self-contained investigation report."""
    risk = result.risk
    icon = RISK_ICONS.get(risk.level, "⚪")

    lines: list[str] = [
        "# Phishing Analysis Report",
        "",
        f"**Tool:** {APP_NAME} v{APP_VERSION}  ",
        f"**Report ID:** `{result.id}`  ",
        f"**Generated:** {_format_time(result.created_at)}  ",
        f"**Source:** {_cell(result.source)}",
        "",
        "> All indicators are defanged (for example `hxxps://evil[.]example`).",
        "> No link was opened and no email was sent during this analysis.",
        "",
        "## 1. Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Subject | {_cell(result.subject or '(no subject)')} |",
        f"| From | {_cell(result.sender or '(unknown)')} |",
        f"| Reply-To | {_cell(result.message_info.get('reply_to', '—'))} |",
        f"| Recipients | {_cell(', '.join(result.recipients) or '—')} |",
        f"| Attachments | {len(result.attachments)} |",
        f"| Indicators | {len(result.iocs)} |",
        "",
        f"### {icon} {risk.level.value} risk — {risk.score}/100",
        "",
        risk.summary,
        "",
    ]

    if risk.unknown_reputation:
        lines.extend(
            [
                "> **Reputation not verified.** VirusTotal was not run, or every lookup "
                "returned unknown/error. This is *not* the same as a clean result.",
                "",
            ]
        )

    lines.extend(["## 2. Score breakdown", ""])
    if risk.breakdown:
        lines.extend(
            [
                "| Category | Points | Cap | Findings |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for item in risk.breakdown:
            lines.append(
                f"| {item['category']} | {item['points']} | "
                f"{item['max_points']} | {item['findings']} |"
            )
        lines.append("")
    else:
        lines.extend(["No scoring findings were produced.", ""])

    lines.extend(["## 3. Findings", ""])
    if not result.findings:
        lines.extend(["No findings.", ""])
    for severity in SEVERITY_ORDER:
        group = result.findings_by_severity(severity)
        if not group:
            continue
        lines.append(f"### {SEVERITY_ICONS[severity]} {severity.value} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.append(f"- **{_cell(finding.title)}** — {_cell(finding.detail)}")
            if finding.evidence:
                lines.append(f"  - Evidence: {_code(finding.evidence)}")
        lines.append("")

    lines.extend(
        [
            "## 4. Indicators of compromise",
            "",
        ]
    )
    if result.iocs:
        lines.extend(
            [
                "| Type | Indicator (defanged) | Occurrences |",
                "| --- | --- | ---: |",
            ]
        )
        for ioc in result.iocs:
            lines.append(
                f"| {ioc.kind} | `{_cell(defang(ioc.value))}` | {ioc.count} |"
            )
        lines.append("")
    else:
        lines.extend(["No indicators were extracted.", ""])

    lines.extend(["## 5. Reputation", ""])
    if result.reputations:
        lines.extend(
            [
                "| Type | Indicator | Verdict | Engines | Note |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in result.reputations:
            engines = (
                f"{item.malicious + item.suspicious}/{item.total_engines}"
                if item.total_engines
                else "—"
            )
            lines.append(
                f"| {item.ioc_kind} | `{_cell(defang(item.value))}` | "
                f"{_reputation_label(item.verdict)} | {engines} | {_cell(item.note)} |"
            )
        lines.append("")
    else:
        lines.extend(
            [
                "VirusTotal lookup was **not performed** for this analysis.",
                "Unknown reputation must not be treated as safe.",
                "",
            ]
        )

    if result.attachments:
        lines.extend(
            [
                "## 6. Attachments (metadata only)",
                "",
                "| Filename | Type | Size |",
                "| --- | --- | ---: |",
            ]
        )
        for attachment in result.attachments:
            lines.append(
                f"| {_cell(attachment.filename)} | {_cell(attachment.content_type)} | "
                f"{attachment.size_bytes:,} bytes |"
            )
        lines.append("")

    lines.extend(
        [
            "## 7. AI / analyst explanation",
            "",
            result.ai_explanation or "No explanation was generated.",
            "",
        ]
    )
    if result.ai_note:
        lines.extend([f"*{_cell(result.ai_note)}*", ""])

    lines.extend(["## 8. Recommended actions", ""])
    lines.extend(f"- {action}" for action in _recommended_actions(result))

    # MITRE ATT&CK Matrix Mapping
    mitre_techniques: dict[str, tuple[str, list[str]]] = {}
    for finding in result.findings:
        if finding.mitre_id:
            if finding.mitre_id not in mitre_techniques:
                mitre_techniques[finding.mitre_id] = (finding.mitre_name or "Phishing", [])
            mitre_techniques[finding.mitre_id][1].append(finding.title)

    if mitre_techniques:
        lines.extend(
            [
                "",
                "## 9. MITRE ATT&CK Matrix Mapping",
                "",
                "| Technique ID | Technique Name | Detected Signals |",
                "| --- | --- | --- |",
            ]
        )
        for tid, (tname, titles) in sorted(mitre_techniques.items()):
            signal_summary = _cell("; ".join(list(dict.fromkeys(titles))[:3]))
            lines.append(f"| `{tid}` | {_cell(tname)} | {signal_summary} |")

    lines.extend(
        [
            "",
            "## 10. Message details",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
    )
    for key, value in result.message_info.items():
        lines.append(f"| {_cell(key)} | {_cell(value)} |")
    lines.extend(
        [
            "",
            "---",
            "",
            "*Generated locally by the AI-Assisted Phishing Analysis Tool. "
            "Header and body checks are heuristics, not a definitive verdict.*",
            "",
        ]
    )
    return "\n".join(lines)


def build_soc_ticket(result: AnalysisResult) -> str:
    """Format an incident ticket note ready to paste into Jira, TheHive, or ServiceNow."""
    stamp = _format_time(result.created_at)
    risk = result.risk
    actions = _recommended_actions(result)

    mitre_summary = []
    seen_mitre = set()
    for f in result.findings:
        if f.mitre_id and f.mitre_id not in seen_mitre:
            seen_mitre.add(f.mitre_id)
            mitre_summary.append(f"{f.mitre_id} ({f.mitre_name or 'Phishing'})")

    extracted_urls = [defang(ioc.value) for ioc in result.iocs_of_kind("url")[:6]]
    extracted_domains = [defang(ioc.value) for ioc in result.iocs_of_kind("domain")[:6]]
    extracted_ips = [defang(ioc.value) for ioc in result.iocs_of_kind("ip")[:6]]

    lines = [
        "=== SOC INCIDENT TRIAGE NOTE ===",
        f"Incident Ref: SEC-PHISH-{result.id}",
        f"Triage Timestamp: {stamp}",
        f"Risk Level: {risk.level.value.upper()} ({risk.score}/100)",
        f"Subject: {result.subject or '(No Subject)'}",
        f"From: {result.sender or '(Unknown Sender)'}",
        f"Reply-To: {result.message_info.get('reply_to', '—')}",
        "",
        "--- EXECUTIVE SUMMARY ---",
        risk.summary,
        "",
        "--- MITRE ATT&CK TECHNIQUES ---",
        ", ".join(mitre_summary) if mitre_summary else "T1566 (Phishing)",
        "",
        "--- KEY FINDINGS ---",
    ]

    for f in result.findings_sorted[:6]:
        if f.severity.value != "Info":
            lines.append(f"- [{f.severity.value}] {f.title}: {f.detail}")

    lines.extend([
        "",
        "--- EXTRACTED IOCs (DEFANGED) ---",
        f"URLs: {', '.join(extracted_urls) if extracted_urls else 'None'}",
        f"Domains: {', '.join(extracted_domains) if extracted_domains else 'None'}",
        f"IPs: {', '.join(extracted_ips) if extracted_ips else 'None'}",
        "",
        "--- RECOMMENDED CONTAINMENT PLAYBOOK ---",
    ])
    for idx, act in enumerate(actions, 1):
        lines.append(f"{idx}. {act}")

    return "\n".join(lines)


def build_ioc_blocklist(result: AnalysisResult, format_type: str = "plain") -> str:
    """Export network IOCs (domains and IPs) for perimeter blocklists."""
    domains = [ioc.value for ioc in result.iocs_of_kind("domain")]
    ips = [ioc.value for ioc in result.iocs_of_kind("ip")]
    for ioc in result.iocs_of_kind("url"):
        try:
            from urllib.parse import urlsplit
            host = (urlsplit(ioc.value).hostname or "").strip().lower()
            if host and host not in domains:
                domains.append(host)
        except Exception:
            pass

    unique_domains = sorted(set(domains))
    unique_ips = sorted(set(ips))

    if format_type == "csv":
        lines = ["indicator,type,first_seen_id"]
        for domain in unique_domains:
            lines.append(f"{domain},domain,{result.id}")
        for ip in unique_ips:
            lines.append(f"{ip},ip,{result.id}")
        return "\n".join(lines)

    lines = [
        f"# Perimeter Blocklist Export - Incident SEC-PHISH-{result.id}",
        f"# Generated: {_format_time(result.created_at)}",
        "# Domains:",
    ]
    lines.extend(unique_domains or ["# No domains"])
    lines.append("\n# IP Addresses:")
    lines.extend(unique_ips or ["# No IPs"])
    return "\n".join(lines)


def build_json(result: AnalysisResult) -> str:
    """Full structured result for downstream tooling."""
    payload = {
        "report_version": 1,
        "tool": APP_NAME,
        "tool_version": APP_VERSION,
        "result": result.to_dict(),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
