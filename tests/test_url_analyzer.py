from app.analyzer.email_parser import ParsedEmail
from app.analyzer.url_analyzer import analyze_urls, extract_urls


def titles(findings):
    return {f.title for f in findings}


def test_extracts_from_html_and_text_without_duplicates():
    e = ParsedEmail(body_html='<a href="http://a.com/x">click</a>',
                    body_text="see http://a.com/x and https://b.org/y.")
    urls = [u["url"] for u in extract_urls(e)]
    assert sorted(urls) == ["http://a.com/x", "https://b.org/y"]


def test_detects_ip_based_url():
    f, _ = analyze_urls(ParsedEmail(body_text="go to http://185.220.101.45/login"))
    assert "IP-based URL" in titles(f)


def test_detects_link_text_mismatch():
    html = '<a href="http://evil.example/x">https://www.paypal.com/verify</a>'
    f, _ = analyze_urls(ParsedEmail(body_html=html))
    assert "Suspicious URL" in titles(f)


def test_matching_link_text_is_not_flagged():
    html = '<a href="https://www.example.com/a">example.com</a>'
    f, _ = analyze_urls(ParsedEmail(body_html=html))
    assert "Suspicious URL" not in titles(f)


def test_detects_shortener():
    f, _ = analyze_urls(ParsedEmail(body_text="https://bit.ly/3abc"))
    assert "URL shortener" in titles(f)


def test_detects_at_sign_trick_and_lookalike():
    f, _ = analyze_urls(ParsedEmail(body_text="http://paypal.com@evil.example/login http://paypa1-secure.xyz/a"))
    assert "Suspicious URL domain" in titles(f)


def test_clean_url_has_no_findings():
    f, urls = analyze_urls(ParsedEmail(body_text="docs at https://www.python.org/downloads"))
    assert f == [] and len(urls) == 1
