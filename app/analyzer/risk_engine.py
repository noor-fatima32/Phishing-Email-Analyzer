"""Risk engine: turns findings into a score, a level, and an explanation.

Also exposes analyze_email(), the single entry point used by the CLI and web UI:
    raw email -> parse -> run analyzers -> score -> JSON-friendly result dict
"""
from app.analyzer.content_analyzer import analyze_content
from app.analyzer.email_parser import parse_email
from app.analyzer.header_analyzer import analyze_headers
from app.analyzer.url_analyzer import analyze_urls

MAX_SCORE = 100
LOW_MAX, MEDIUM_MAX = 29, 59   # 0-29 LOW | 30-59 MEDIUM | 60-100 HIGH

VERDICTS = {
    "LOW": (
        "Low probability of phishing. No strong indicators were found.",
        "Stay cautious anyway: automated checks can't prove an email is safe. "
        "Verify any unexpected request through an official channel.",
    ),
    "MEDIUM": (
        "Suspicious. Several phishing indicators were found.",
        "Treat with caution. Don't click links or open attachments until you've "
        "verified the sender through a separate, trusted channel.",
    ),
    "HIGH": (
        "High probability of phishing.",
        "Do not click links or provide credentials. Don't reply. "
        "Report the email to your IT/security team and delete it.",
    ),
}


def risk_level(score: int) -> str:
    if score <= LOW_MAX:
        return "LOW"
    return "MEDIUM" if score <= MEDIUM_MAX else "HIGH"


def calculate_risk(findings: list) -> dict:
    """Sum finding weights (capped at 100) and attach level, verdict, recommendation."""
    raw = sum(f.weight for f in findings)
    score = min(MAX_SCORE, raw)
    level = risk_level(score)
    verdict, recommendation = VERDICTS[level]
    return {"risk_score": score, "raw_score": raw, "risk_level": level,
            "verdict": verdict, "recommendation": recommendation}


def analyze_email(raw) -> dict:
    """Run the full pipeline on raw email (str or bytes). Raises ValueError on bad input."""
    email = parse_email(raw)
    url_findings, urls = analyze_urls(email)

    # Highest weight first; sort is stable so ties keep detection order.
    findings = sorted(analyze_headers(email) + url_findings + analyze_content(email),
                      key=lambda f: -f.weight)

    sender = f'{email.from_name} <{email.from_address}>' if email.from_name else email.from_address
    result = {
        "email": {
            "from": sender,
            "reply_to": email.reply_to_address,
            "return_path": email.return_path,
            "subject": email.subject,
            "date": email.date,
            "attachments": [a["filename"] for a in email.attachments],
        },
        "findings": [f.to_dict() for f in findings],
        "indicators": list(dict.fromkeys(f.indicator for f in findings)),  # unique, ordered
        "urls": urls,
        "has_headers": email.has_headers,
        "notice": (None if email.has_headers else
                   "No email headers were detected, so this was analyzed as plain message "
                   "text only (urgency language, credential requests, and links). Paste the "
                   "full email source, including headers such as From/Reply-To, for sender "
                   "and domain-spoofing checks too."),
    }
    result.update(calculate_risk(findings))
    return result
