from core.ioc_extractor import defang, extract_iocs, refang


def test_refang_handles_common_defanging():
    assert refang("hxxps://bad[.]example[.]com") == "https://bad.example.com"
    assert refang("user[at]example[.]com") == "user@example.com"
    assert refang("hxxp://a(.)b[.]c[:]8080") == "http://a.b.c:8080"


def test_defang_round_trip():
    original = "https://evil.example/login?user=admin@example.com"
    assert refang(defang(original)) == original


def test_extracts_all_four_kinds():
    text = (
        "Contact admin@example.com or open hxxps://evil[.]example/login. "
        "The sending server was 203.0.113.9."
    )
    iocs = extract_iocs(text)
    by_kind: dict[str, list[str]] = {}
    for ioc in iocs:
        by_kind.setdefault(ioc.kind, []).append(ioc.value)

    assert "https://evil.example/login" in by_kind["url"]
    assert "admin@example.com" in by_kind["email"]
    assert "203.0.113.9" in by_kind["ip"]
    assert "evil.example" in by_kind["domain"]


def test_deduplicates_and_counts_occurrences():
    text = "Visit https://a.example/x and again https://a.example/x."
    urls = [ioc for ioc in extract_iocs(text) if ioc.kind == "url"]
    assert len(urls) == 1
    assert urls[0].count == 2


def test_ignores_file_names_that_look_like_domains():
    iocs = extract_iocs("The file is invoice.pdf and logo.png")
    domains = [ioc.value for ioc in iocs if ioc.kind == "domain"]
    assert "invoice.pdf" not in domains
    assert "logo.png" not in domains


def test_url_trailing_punctuation_is_removed():
    iocs = extract_iocs("See https://example.com/path, then continue.")
    urls = [ioc.value for ioc in iocs if ioc.kind == "url"]
    assert urls == ["https://example.com/path"]
