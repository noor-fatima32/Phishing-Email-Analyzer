from pathlib import Path

import pytest

from app.analyzer.email_parser import get_domain, parse_email

SAMPLES = Path(__file__).parent.parent / "samples"


def load(name):
    return (SAMPLES / name).read_bytes()


def test_parses_suspicious_sample_headers():
    e = parse_email(load("suspicious_email.eml"))
    assert e.from_name == "PayPal Security"
    assert e.from_domain == "paypa1-support.com"
    assert e.reply_to_domain == "gmail.com"
    assert e.return_path_domain == "mailer-x9.example"
    assert e.subject.startswith("Urgent")
    assert "spf=fail" in e.auth_results


def test_extracts_text_and_html_bodies():
    e = parse_email(load("suspicious_email.eml"))
    assert "185.220.101.45" in e.body_text
    assert "<a href=" in e.body_html


def test_safe_sample_has_no_html_or_attachments():
    e = parse_email(load("safe_email.eml"))
    assert e.from_address == "sarah.khan@example.com"
    assert e.body_html == "" and e.attachments == []


def test_accepts_plain_string_input():
    e = parse_email("From: a@b.com\nSubject: Hi\n\nBody here")
    assert e.from_domain == "b.com" and "Body here" in e.body_text


@pytest.mark.parametrize("bad", ["", "   \n"])
def test_rejects_empty_input(bad):
    with pytest.raises(ValueError):
        parse_email(bad)


def test_plain_text_with_no_headers_is_analyzed_as_body():
    """Someone just types/pastes a message with no headers - don't reject it,
    treat the whole thing as body text so content/URL analysis still runs."""
    e = parse_email("just random text with no headers, click http://bit.ly/x now")
    assert e.has_headers is False
    assert e.from_address == "" and e.subject == ""
    assert "click http://bit.ly/x now" in e.body_text


def test_full_email_source_sets_has_headers_true():
    e = parse_email("From: a@b.com\nSubject: Hi\n\nBody here")
    assert e.has_headers is True


def test_get_domain():
    assert get_domain("User@Example.COM") == "example.com"
    assert get_domain("no-at-sign") == ""
