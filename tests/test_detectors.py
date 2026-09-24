from app.analyzer.content_analyzer import analyze_content
from app.analyzer.email_parser import ParsedEmail, parse_email
from app.analyzer.header_analyzer import analyze_headers
from app.utils.helpers import brand_text_mentions, domain_red_flags


def titles(findings):
    return {f.title for f in findings}


def test_lookalike_domains_flagged():
    assert domain_red_flags("paypa1-support.com")
    assert domain_red_flags("rnicrosoft-online.com")
    assert domain_red_flags("paypal.com.evil.io")


def test_fuzzy_typosquat_domains_flagged():
    """Doubled/dropped/swapped letters, not just leet-substitution or prefix tricks."""
    for d in ("instagraam.com", "paypall.com", "micosoft.com", "faceboook.com", "linkedln.com"):
        assert domain_red_flags(d), d


def test_bare_email_address_input_flags_domain_impersonation():
    """Pasting just a sender address (no headers at all) should still run domain checks."""
    e = parse_email("info@instagraam.com")
    assert e.has_headers is False
    assert e.from_domain == "instagraam.com"
    findings = analyze_headers(e)
    assert any(f.indicator == "Domain impersonation" for f in findings)


def test_legit_and_unrelated_domains_clean():
    for d in ("paypal.com", "mail.paypal.com", "amazon.co.uk", "pineapple.com", "example.com"):
        assert domain_red_flags(d) == [], d


def test_header_findings_on_spoofed_email():
    e = parse_email(open("samples/suspicious_email.eml", "rb").read())
    t = titles(analyze_headers(e))
    assert {"Suspicious sender domain", "Brand impersonation", "Reply-To mismatch",
            "Email authentication failed"} <= t


def test_related_reply_to_domain_not_flagged():
    e = ParsedEmail(from_domain="example.com", reply_to_domain="mail.example.com")
    assert "Reply-To mismatch" not in titles(analyze_headers(e))


def test_content_urgency_and_credentials():
    e = ParsedEmail(subject="Urgent", body_text="Please confirm your password within 24 hours.")
    t = titles(analyze_content(e))
    assert {"Urgency detected", "Credential request"} <= t


def test_normal_text_not_flagged():
    e = ParsedEmail(subject="Lunch", body_text="Want to grab lunch on Friday?")
    assert analyze_content(e) == []


def test_risky_attachment():
    e = ParsedEmail(attachments=[{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream"}])
    assert "Risky attachment" in titles(analyze_content(e))


def test_misspelled_brand_name_in_body_text_flagged():
    """No link, no domain - just a misspelled brand name in the subject/body/sign-off,
    like 'Instagraam' - should still be caught as brand spoofing."""
    email = ParsedEmail(subject="Password reset for Instagraam",
                         body_text="Hi Sara, reset your password. Thanks, The Instagraam Team")
    findings = analyze_content(email)
    assert any(f.indicator == "Brand name spoofing" for f in findings)


def test_correct_brand_spelling_and_ordinary_words_not_flagged():
    assert brand_text_mentions("Thanks for using Instagram and Netflix today.") == []
    assert brand_text_mentions("This is about pineapples and apples.") == []


def test_password_reset_wording_flagged_as_credential_request():
    email = ParsedEmail(body_text="We received a request to reset the password for your account.")
    findings = analyze_content(email)
    assert any(f.indicator == "Credential request" for f in findings)
