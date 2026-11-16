import pytest
import requests

from core.pipeline import analyze_email_text
from core.samples import list_samples, load_sample_text


@pytest.mark.parametrize("sample", list_samples(), ids=lambda item: item.key)
def test_sample_scores_match_documented_expectation(sample):
    result = analyze_email_text(load_sample_text(sample.key), source=sample.title)
    assert result.risk.level.value == sample.expected
    assert result.ai_used is False
    assert result.ai_explanation


def test_malware_sample_lists_attachment_without_opening_it():
    result = analyze_email_text(load_sample_text("malware_lure"))
    assert len(result.attachments) == 1
    assert result.attachments[0].filename == "Delivery_Invoice.docm"
    assert any("Macro-capable" in item.title for item in result.findings)


def test_legitimate_sample_scores_low():
    result = analyze_email_text(load_sample_text("legitimate"))
    assert result.risk.score < 25
    # IOCs exist but no lookup was run, so reputation is explicitly unknown.
    assert result.risk.unknown_reputation is True


def test_offline_analysis_never_makes_a_network_call(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("A network request was attempted during offline analysis")

    monkeypatch.setattr(requests.Session, "get", explode)
    monkeypatch.setattr(requests, "get", explode)

    result = analyze_email_text(load_sample_text("credential_phish"))
    assert result.risk.score > 0


def test_unknown_reputation_is_explicit(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    result = analyze_email_text(load_sample_text("bec_invoice"))
    assert result.reputation_checked is False
    assert result.risk.unknown_reputation is True
    assert "unknown" in result.ai_explanation.lower()
