"""Regression tests: every bundled sample must keep its expected verdict."""
from pathlib import Path

import pytest

from app.analyzer.risk_engine import analyze_email

SAMPLES = Path(__file__).parent.parent / "samples"

EXPECTED = [
    ("suspicious_email.eml", "HIGH", 100),
    ("parcel_notice.eml", "MEDIUM", 45),
    ("invoice_attachment.eml", "HIGH", 80),
    ("safe_email.eml", "LOW", 0),
]


@pytest.mark.parametrize("name,level,score", EXPECTED)
def test_sample_verdicts(name, level, score):
    r = analyze_email((SAMPLES / name).read_bytes())
    assert (r["risk_level"], r["risk_score"]) == (level, score)


def test_invoice_flags_double_extension_attachment():
    r = analyze_email((SAMPLES / "invoice_attachment.eml").read_bytes())
    assert r["email"]["attachments"] == ["Invoice_8841.pdf.exe"]
    assert "Risky attachment" in r["indicators"]


def test_parcel_uses_shortener_and_reply_to_mismatch():
    r = analyze_email((SAMPLES / "parcel_notice.eml").read_bytes())
    assert {"URL shortener", "Reply-To mismatch"} <= set(r["indicators"])
