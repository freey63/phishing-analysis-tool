"""Convert findings into a bounded 0-100 risk score.

Each category has a cap so one noisy heuristic family cannot dominate the
result. The breakdown is always shown to the user, so the score is explainable.
"""

from __future__ import annotations

from collections import defaultdict

from core.models import (
    Finding,
    Reputation,
    ReputationVerdict,
    RiskAssessment,
    RiskLevel,
    Severity,
)

CATEGORY_CAPS: dict[str, int] = {
    "Header": 40,
    "Body": 40,
    "URL": 40,
    "Reputation": 50,
    "Attachment": 25,
    "Other": 20,
}

CATEGORY_ORDER = ["Header", "Body", "URL", "Reputation", "Attachment", "Other"]

# Bands are deliberately documented in the README.
LEVEL_THRESHOLDS: tuple[tuple[int, RiskLevel], ...] = (
    (75, RiskLevel.CRITICAL),
    (50, RiskLevel.HIGH),
    (25, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
)


def level_for_score(score: int) -> RiskLevel:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def score_findings(
    findings: list[Finding],
    *,
    reputation_checked: bool = False,
    ioc_count: int = 0,
    reputations: list[Reputation] | None = None,
) -> RiskAssessment:
    """Score findings and explain where the points came from."""
    totals: dict[str, int] = defaultdict(int)
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        totals[finding.category] += finding.weight
        counts[finding.category] += 1

    breakdown: list[dict[str, int | str]] = []
    score = 0
    for category in CATEGORY_ORDER:
        if counts.get(category, 0) == 0:
            continue
        cap = CATEGORY_CAPS.get(category, 20)
        points = min(totals.get(category, 0), cap)
        score += points
        breakdown.append(
            {
                "category": category,
                "points": points,
                "max_points": cap,
                "findings": counts[category],
            }
        )

    score = min(100, max(0, score))
    level = level_for_score(score)

    reputations = reputations or []
    all_unverified = bool(reputations) and all(
        item.verdict in {ReputationVerdict.UNKNOWN, ReputationVerdict.ERROR}
        for item in reputations
    )
    unknown_reputation = bool(ioc_count) and (
        not reputation_checked or all_unverified or not reputations
    )

    # Short summary from the strongest, non-reputation findings.
    headline_findings = [
        finding.title
        for finding in sorted(findings, key=lambda item: item.weight, reverse=True)
        if finding.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    ][:3]

    if headline_findings:
        summary = (
            f"{level.value} risk ({score}/100). Main signals: "
            + "; ".join(dict.fromkeys(headline_findings))
            + "."
        )
    else:
        summary = (
            f"{level.value} risk ({score}/100). No strong phishing indicators were "
            "detected by the rule set."
        )

    if unknown_reputation:
        summary += " Reputation was not verified for all indicators."

    return RiskAssessment(
        score=score,
        level=level,
        breakdown=breakdown,
        unknown_reputation=unknown_reputation,
        summary=summary,
    )
