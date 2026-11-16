from core.models import IOC, Severity
from core.url_analyzer import analyze_iocs


def _url(value: str):
    return analyze_iocs([IOC(kind="url", value=value)])


def test_raw_ip_host_is_high_severity():
    findings = _url("http://203.0.113.5/login")
    assert any("IP address" in item.title for item in findings)
    assert any(item.severity == Severity.HIGH for item in findings)


def test_brand_inside_unrelated_domain_is_flagged():
    findings = _url("https://paypal.com.account-check.evil.example/login")
    assert any("paypal" in item.title.lower() for item in findings)


def test_typosquatted_domain_is_flagged():
    findings = _url("https://micros0ft.com/login")
    assert any("Lookalike" in item.title for item in findings)


def test_shortener_is_flagged():
    findings = _url("https://bit.ly/3xParcel")
    assert any("shortener" in item.title.lower() for item in findings)


def test_dangerous_attachment_url_is_flagged():
    findings = _url("https://example.com/files/invoice.pdf.exe")
    assert any("executable" in item.title.lower() for item in findings)


def test_clean_url_has_no_findings():
    assert _url("https://example.com/newsletter/november") == []


def test_standalone_suspicious_domain_is_analysed():
    findings = analyze_iocs([IOC(kind="domain", value="login-verify.top")])
    assert any("top-level domain" in item.title for item in findings)
