from core.models import Finding, Reputation, ReputationVerdict, RiskLevel, Severity
from core.scoring import level_for_score, score_findings


def _finding(severity: Severity, category: str = "Header") -> Finding:
    return Finding(category=category, title="test", detail="", severity=severity)


def test_risk_bands():
    assert level_for_score(0) == RiskLevel.LOW
    assert level_for_score(24) == RiskLevel.LOW
    assert level_for_score(25) == RiskLevel.MEDIUM
    assert level_for_score(49) == RiskLevel.MEDIUM
    assert level_for_score(50) == RiskLevel.HIGH
    assert level_for_score(74) == RiskLevel.HIGH
    assert level_for_score(75) == RiskLevel.CRITICAL
    assert level_for_score(100) == RiskLevel.CRITICAL


def test_category_cap_prevents_score_inflation():
    findings = [_finding(Severity.HIGH, "URL") for _ in range(10)]
    clean = [
        Reputation(
            ioc_kind="url",
            value="https://example.com",
            verdict=ReputationVerdict.CLEAN,
            harmless=60,
            total_engines=60,
        )
    ]
    risk = score_findings(
        findings, reputation_checked=True, ioc_count=1, reputations=clean
    )
    assert risk.score == 40  # URL cap
    assert risk.level == RiskLevel.MEDIUM
    assert risk.breakdown[0]["points"] == 40


def test_unknown_reputation_when_lookup_skipped():
    risk = score_findings(
        [_finding(Severity.LOW)], reputation_checked=False, ioc_count=3
    )
    assert risk.unknown_reputation is True


def test_unknown_reputation_when_lookup_fails():
    failed = [
        Reputation(
            ioc_kind="domain",
            value="bad.example",
            verdict=ReputationVerdict.ERROR,
        )
    ]
    risk = score_findings(
        [_finding(Severity.MEDIUM)],
        reputation_checked=True,
        ioc_count=1,
        reputations=failed,
    )
    assert risk.unknown_reputation is True


def test_no_iocs_means_no_unknown_reputation_warning():
    risk = score_findings([], reputation_checked=False, ioc_count=0)
    assert risk.unknown_reputation is False
    assert risk.score == 0
    assert risk.level == RiskLevel.LOW
