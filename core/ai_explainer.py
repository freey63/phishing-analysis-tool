"""Optional AI explanation layer.

The model receives only structured findings plus a short list of defanged
indicators. The raw body is included only when the user explicitly consents.
If OpenAI is unavailable, a deterministic local explanation is returned so the
feature always degrades gracefully.
"""

from __future__ import annotations

import json
from typing import Any

from config import OPENAI_TIMEOUT
from core.ioc_extractor import defang
from core.models import (
    AnalysisResult,
    ReputationVerdict,
    RISK_ICONS,
    Severity,
)


SYSTEM_PROMPT = """You are a defensive SOC analyst assistant writing for a beginner.

Explain the phishing assessment you are given, using ONLY the facts provided.
Rules:
- Never invent facts, vendors, senders or verdicts that are not in the data.
- Never describe an unchecked or "unknown" indicator as safe.
- Never tell the reader to visit, click or open any link or attachment.
- Be concise: at most 250 words.
- Use plain English and short sections: "What stands out", "How risky is it",
  "What to do next".
- Mention that header/body checks are heuristics, not a guaranteed verdict.
"""


def _top_findings(result: AnalysisResult, limit: int = 6) -> list[str]:
    lines: list[str] = []
    for finding in result.findings_sorted:
        if finding.severity == Severity.INFO:
            continue
        lines.append(f"- **{finding.title}** ({finding.severity.value}): {finding.detail}")
        if len(lines) >= limit:
            break
    return lines


def _reputation_sentence(result: AnalysisResult) -> str:
    if not result.reputations:
        return (
            "No reputation lookup was performed, so every indicator is "
            "**unknown / unverified**, not safe."
        )
    malicious = [
        item for item in result.reputations if item.verdict == ReputationVerdict.MALICIOUS
    ]
    suspicious = [
        item
        for item in result.reputations
        if item.verdict == ReputationVerdict.SUSPICIOUS
    ]
    if malicious:
        return (
            f"VirusTotal flagged {len(malicious)} indicator(s) as malicious. "
            "Treat the message as dangerous."
        )
    if suspicious:
        return f"VirusTotal marked {len(suspicious)} indicator(s) as suspicious."
    if all(
        item.verdict in {ReputationVerdict.UNKNOWN, ReputationVerdict.ERROR}
        for item in result.reputations
    ):
        return "VirusTotal returned no usable result, so reputation remains **unknown**."
    return (
        "VirusTotal did not flag the checked indicators, but a clean reputation "
        "is not proof that a message is safe."
    )


def fallback_explanation(result: AnalysisResult) -> str:
    """A useful explanation that needs no network access."""
    risk = result.risk
    icon = RISK_ICONS.get(risk.level, "⚪")
    parts: list[str] = [
        f"### {icon} {risk.level.value} risk ({risk.score}/100)",
        "",
        risk.summary,
        "",
    ]

    lines = _top_findings(result)
    parts.append("**What stands out**")
    parts.append("")
    if lines:
        parts.extend(lines)
    else:
        parts.append(
            "- No strong phishing indicators were detected by the header, body or "
            "URL rules. This does not guarantee the email is safe."
        )
    parts.extend(["", "**Reputation**", "", f"- {_reputation_sentence(result)}", ""])

    parts.extend(["**What to do next**", ""])
    if risk.level.value in {"High", "Critical"}:
        parts.extend(
            [
                "- Do not click links, open attachments, or reply.",
                "- Report the message to your security team and keep the original headers.",
                "- If credentials were entered, reset the password and revoke sessions.",
            ]
        )
    elif risk.level.value == "Medium":
        parts.extend(
            [
                "- Verify the sender through a separate channel before acting.",
                "- Inspect links in an isolated sandbox - never on your workstation.",
            ]
        )
    else:
        parts.extend(
            [
                "- No action is required based on the rules, but stay cautious.",
                "- If the message asks for money, credentials or secrecy, verify it out-of-band.",
            ]
        )
    parts.extend(
        [
            "",
            "*Rule-based explanation. Header and body checks are heuristics, not a "
            "definitive verdict.*",
        ]
    )
    return "\n".join(parts)


def _facts(result: AnalysisResult, body_text: str | None) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "risk": {
            "score": result.risk.score,
            "level": result.risk.level.value,
            "unknown_reputation": result.risk.unknown_reputation,
            "score_breakdown": result.risk.breakdown,
        },
        "message": {
            "subject": result.subject,
            "from": result.sender,
            "reply_to": result.message_info.get("reply_to"),
            "authentication_results": result.message_info.get(
                "authentication_results"
            ),
            "attachment_names": [item.filename for item in result.attachments],
        },
        "findings": [
            {
                "severity": finding.severity.value,
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
            }
            for finding in result.findings_sorted
            if finding.severity != Severity.INFO
        ],
        "indicators": [
            {"type": ioc.kind, "value": defang(ioc.value)} for ioc in result.iocs[:25]
        ],
        "reputation": [
            {
                "type": item.ioc_kind,
                "value": defang(item.value),
                "verdict": item.verdict.value,
                "note": item.note,
            }
            for item in result.reputations
        ],
    }
    if body_text:
        facts["body_excerpt"] = body_text[:1500]
    return facts


def explain(
    result: AnalysisResult,
    *,
    api_key: str,
    model: str,
    include_body: bool = False,
    body_text: str = "",
) -> tuple[str, bool, str]:
    """Return ``(explanation, used_ai, note)``.

    Never raises: any failure falls back to the local explanation.
    """
    if not api_key:
        return (
            fallback_explanation(result),
            False,
            "No OpenAI API key configured - showing the built-in explanation.",
        )

    try:
        from openai import OpenAI
    except ImportError:
        return (
            fallback_explanation(result),
            False,
            "The openai package is not installed - showing the built-in explanation.",
        )

    facts = _facts(result, body_text if include_body else None)
    user_prompt = (
        "Here is the structured assessment as JSON:\n\n"
        + json.dumps(facts, indent=2, ensure_ascii=False)
        + "\n\nWrite the explanation now."
    )

    try:
        client = OpenAI(
            api_key=api_key,
            timeout=OPENAI_TIMEOUT,
            max_retries=1,
        )
        response = client.chat.completions.create(
            model=model,
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = (response.choices[0].message.content or "").strip()
        if not text:
            raise ValueError("empty response")
    except Exception:  # noqa: BLE001 - degrade gracefully, never leak details
        return (
            fallback_explanation(result),
            False,
            "AI request failed - showing the built-in explanation.",
        )

    return text, True, f"Generated by {model} from the structured findings."
