from datetime import datetime, timezone
from email.utils import format_datetime

from core.email_parser import parse_email
from core.header_analyzer import analyze_headers
from core.models import Severity


def _dated_email(extra_headers: str, body: str = "Hello") -> str:
    now = format_datetime(datetime.now(timezone.utc))
    return f"{extra_headers}\nDate: {now}\n\n{body}"


def test_flags_reply_to_mismatch_and_auth_failure():
    raw = _dated_email(
        'From: "Microsoft Support" <security@micros0ft.com>\n'
        "To: victim@example.org\n"
        "Reply-To: help@evil.example\n"
        "Subject: Verify your account immediately\n"
        "Message-ID: <1@micros0ft.com>\n"
        "Authentication-Results: mx.example.org; spf=fail; dmarc=fail"
    )
    findings = analyze_headers(parse_email(raw))
    titles = [finding.title for finding in findings]

    assert any("Reply-To" in title for title in titles)
    assert any("DMARC" in title for title in titles)
    assert any("SPF" in title for title in titles)
    assert any("Brand name in display name" in title for title in titles)


def test_legitimate_headers_produce_no_high_severity_findings():
    raw = _dated_email(
        "From: Example News <news@example.com>\n"
        "To: subscriber@example.org\n"
        "Reply-To: news@example.com\n"
        "Return-Path: <bounce@example.com>\n"
        "Subject: Monthly newsletter\n"
        "Message-ID: <abc@example.com>\n"
        "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass"
    )
    findings = analyze_headers(parse_email(raw))
    assert not [item for item in findings if item.severity == Severity.HIGH]
    assert any("all passed" in item.title for item in findings)


def test_body_only_input_is_reported_as_no_headers():
    findings = analyze_headers(parse_email("Just a body, no headers here."))
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "No email headers" in findings[0].title


def test_future_date_is_flagged():
    raw = (
        "From: a@example.com\nTo: b@example.com\nSubject: hi\n"
        "Date: Fri, 01 Jan 2100 10:00:00 +0000\nMessage-ID: <x@example.com>\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nBody"
    )
    findings = analyze_headers(parse_email(raw))
    assert any("future" in finding.title.lower() for finding in findings)
