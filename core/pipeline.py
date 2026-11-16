"""End-to-end analysis pipeline.

The UI calls exactly one function - ``analyze_email_text`` - which keeps the
Streamlit layer thin and makes the engine easy to test from the command line.
"""

from __future__ import annotations

from typing import Callable

from config import Settings, get_settings
from core.ai_explainer import explain, fallback_explanation
from core.attachment_analyzer import analyze_attachments
from core.email_parser import parse_email
from core.header_analyzer import analyze_headers
from core.ioc_extractor import extract_iocs
from core.models import (
    AnalysisResult,
    Finding,
    Reputation,
    ReputationVerdict,
    Severity,
)
from core.scoring import score_findings
from core.text_analyzer import analyze_body, html_to_text
from core.url_analyzer import analyze_iocs
from core.vt_client import VTClient, VTError

StageCallback = Callable[[str], None]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.category, finding.title, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _reputation_findings(reputations: list[Reputation]) -> list[Finding]:
    findings: list[Finding] = []
    for item in reputations:
        if item.verdict == ReputationVerdict.MALICIOUS:
            findings.append(
                Finding(
                    category="Reputation",
                    title=f"VirusTotal: {item.ioc_kind} flagged as malicious",
                    detail=item.note,
                    severity=Severity.CRITICAL,
                    evidence=item.value,
                    mitre_id="T1566",
                    mitre_name="Phishing: Known Bad Infrastructure",
                )
            )
        elif item.verdict == ReputationVerdict.SUSPICIOUS:
            findings.append(
                Finding(
                    category="Reputation",
                    title=f"VirusTotal: {item.ioc_kind} flagged as suspicious",
                    detail=item.note,
                    severity=Severity.HIGH,
                    evidence=item.value,
                    mitre_id="T1566",
                    mitre_name="Phishing: Suspicious Infrastructure",
                )
            )
        elif item.verdict == ReputationVerdict.ERROR:
            findings.append(
                Finding(
                    category="Reputation",
                    title=f"VirusTotal lookup failed for {item.ioc_kind}",
                    detail=item.note,
                    severity=Severity.INFO,
                    evidence=item.value,
                )
            )
    return findings


def analyze_email_text(
    raw_text: str,
    *,
    source: str = "Pasted email",
    do_reputation: bool = False,
    do_ai: bool = False,
    include_body_in_ai: bool = False,
    max_lookups: int = 4,
    settings: Settings | None = None,
    on_stage: StageCallback | None = None,
) -> AnalysisResult:
    """Analyse one email and return a complete :class:`AnalysisResult`."""
    active_settings = settings or get_settings()

    def stage(message: str) -> None:
        if on_stage:
            on_stage(message)

    stage("Parsing email and MIME parts")
    parsed = parse_email(raw_text, source=source)

    stage("Checking headers and authentication results")
    header_findings = analyze_headers(parsed)

    stage("Analysing body language and links")
    body_findings = analyze_body(parsed)

    stage("Extracting IOCs")
    iocs = extract_iocs(parsed.raw)

    stage("Analysing URLs and domains (static, no requests)")
    url_findings = analyze_iocs(iocs)

    attachment_findings = analyze_attachments(parsed.attachments)

    reputations: list[Reputation] = []
    reputation_findings: list[Finding] = []

    if do_reputation and active_settings.has_vt:
        lookupable = [ioc for ioc in iocs if ioc.kind in {"url", "domain", "ip"}]
        if lookupable:
            stage("Querying VirusTotal reputation")
            client = VTClient(active_settings.vt_api_key)
            try:
                reputations = client.lookup_many(
                    iocs, max_lookups=max_lookups, on_progress=stage
                )
            except VTError as exc:
                stage(f"VirusTotal unavailable: {exc}")
            reputation_findings = _reputation_findings(reputations)

    findings = _dedupe(
        header_findings
        + body_findings
        + url_findings
        + attachment_findings
        + reputation_findings
    )

    risk = score_findings(
        findings,
        reputation_checked=bool(reputations),
        ioc_count=len(iocs),
        reputations=reputations,
    )

    result = AnalysisResult(
        source=source,
        subject=parsed.subject,
        sender=parsed.sender,
        recipients=parsed.recipients,
        findings=findings,
        iocs=iocs,
        reputations=reputations,
        risk=risk,
        reputation_checked=bool(reputations),
        message_info={
            "reply_to": parsed.reply_to or "—",
            "return_path": parsed.return_path or "—",
            "date": parsed.date or "—",
            "message_id": parsed.message_id or "—",
            "received_hops": len(parsed.received),
            "authentication_results": (parsed.auth_results or "—")[:600],
            "has_html_body": bool(parsed.body_html),
            "attachment_count": len(parsed.attachments),
        },
        attachments=parsed.attachments,
    )

    stage("Writing explanation")
    body_for_ai = parsed.body_text or html_to_text(parsed.body_html)
    if do_ai and active_settings.has_openai:
        explanation, used_ai, note = explain(
            result,
            api_key=active_settings.openai_api_key,
            model=active_settings.openai_model,
            include_body=include_body_in_ai,
            body_text=body_for_ai,
        )
    else:
        explanation = fallback_explanation(result)
        used_ai = False
        if not active_settings.has_openai:
            note = (
                "No OpenAI API key configured - showing the built-in explanation."
            )
        else:
            note = "AI explanation disabled - showing the built-in explanation."

    result.ai_explanation = explanation
    result.ai_used = used_ai
    result.ai_note = note

    return result
