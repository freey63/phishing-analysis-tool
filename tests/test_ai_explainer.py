from core.ai_explainer import explain, fallback_explanation
from core.pipeline import analyze_email_text
from core.samples import load_sample_text


def _result():
    return analyze_email_text(load_sample_text("bec_invoice"))


def test_fallback_explanation_is_useful():
    text = fallback_explanation(_result())
    assert "What stands out" in text
    assert "What to do next" in text
    assert "unknown" in text.lower()


def test_explain_without_key_uses_fallback():
    result = _result()
    text, used_ai, note = explain(result, api_key="", model="gpt-4o-mini")
    assert used_ai is False
    assert "No OpenAI API key" in note
    assert "What to do next" in text


def test_ai_note_is_present_when_disabled():
    result = _result()
    assert result.ai_used is False
    assert result.ai_note
    assert "disabled" in result.ai_note.lower() or "built-in" in result.ai_note.lower()
