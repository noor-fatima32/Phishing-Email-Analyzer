from app.analyzer.risk_engine import analyze_email, calculate_risk, risk_level
from app.utils.helpers import Finding


def F(w):
    return Finding("t", "d", w, "i")


def test_level_boundaries():
    assert [risk_level(s) for s in (0, 29, 30, 59, 60, 100)] == \
           ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_score_is_capped_at_100():
    r = calculate_risk([F(60), F(60), F(60)])
    assert r["risk_score"] == 100 and r["raw_score"] == 180 and r["risk_level"] == "HIGH"


def test_no_findings_is_low():
    r = calculate_risk([])
    assert r["risk_score"] == 0 and r["risk_level"] == "LOW"


def test_suspicious_sample_is_high():
    r = analyze_email(open("samples/suspicious_email.eml", "rb").read())
    assert r["risk_level"] == "HIGH" and r["risk_score"] == 100
    assert "Reply-To mismatch" in r["indicators"] and len(r["urls"]) == 1


def test_safe_sample_is_low():
    r = analyze_email(open("samples/safe_email.eml", "rb").read())
    assert r["risk_level"] == "LOW" and r["findings"] == []


def test_medium_case():
    raw = ('From: "Support" <help@example.net>\nReply-To: x@gmail.com\nSubject: Update\n\n'
           "Dear Customer, please verify your password immediately.")
    assert analyze_email(raw)["risk_level"] == "MEDIUM"


def test_findings_sorted_by_weight():
    w = [f["weight"] for f in analyze_email(open("samples/suspicious_email.eml", "rb").read())["findings"]]
    assert w == sorted(w, reverse=True)
