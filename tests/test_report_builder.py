import json

from core.pipeline import analyze_email_text
from core.report_builder import (
    build_ioc_blocklist,
    build_json,
    build_markdown,
    build_soc_ticket,
    report_filename,
)
from core.samples import load_sample_text


def _result():
    return analyze_email_text(load_sample_text("credential_phish"))


def test_markdown_report_has_expected_sections():
    report = build_markdown(_result())
    assert "# Phishing Analysis Report" in report
    assert "## 1. Summary" in report
    assert "## 4. Indicators of compromise" in report
    assert "## 8. Recommended actions" in report
    assert "No link was opened" in report


def test_iocs_are_defanged_in_report():
    result = _result()
    report = build_markdown(result)
    assert "hxxps" in report or "hxxp" in report
    # The raw clickable URL must never appear in the report.
    assert "https://micros0ft.com/login" not in report
    assert "micros0ft[.]com" in report


def test_json_report_round_trips():
    result = _result()
    payload = json.loads(build_json(result))
    assert payload["report_version"] == 1
    assert payload["result"]["id"] == result.id
    assert payload["result"]["risk"]["level"] == result.risk.level.value
    assert payload["result"]["findings"][0]["severity"] in {
        "Info",
        "Low",
        "Medium",
        "High",
        "Critical",
    }


def test_report_filename_is_safe():
    name = report_filename(_result())
    assert name.endswith(".md")
    assert " " not in name
    assert "/" not in name


def test_markdown_report_includes_mitre_mapping():
    report = build_markdown(_result())
    assert "## 9. MITRE ATT&CK Matrix Mapping" in report
    assert "T1566" in report


def test_build_soc_ticket_format():
    ticket = build_soc_ticket(_result())
    assert "=== SOC INCIDENT TRIAGE NOTE ===" in ticket
    assert "Incident Ref: SEC-PHISH-" in ticket
    assert "--- EXECUTIVE SUMMARY ---" in ticket
    assert "--- MITRE ATT&CK TECHNIQUES ---" in ticket
    assert "--- RECOMMENDED CONTAINMENT PLAYBOOK ---" in ticket
    # IOCs in ticket must be defanged
    assert "hxxp" in ticket or "[.]" in ticket


def test_build_ioc_blocklist():
    result = _result()
    plain_bl = build_ioc_blocklist(result, format_type="plain")
    assert "# Perimeter Blocklist Export" in plain_bl
    assert "micros0ft.com" in plain_bl or "203.0.113.9" in plain_bl

    csv_bl = build_ioc_blocklist(result, format_type="csv")
    assert "indicator,type,first_seen_id" in csv_bl
    assert result.id in csv_bl
