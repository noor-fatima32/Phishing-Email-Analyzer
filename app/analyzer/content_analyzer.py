"""Content analysis: does the language pressure or trick the reader?"""
import os
import re

from app.analyzer.email_parser import ParsedEmail
from app.utils.helpers import Finding, brand_name, brand_text_mentions, parse_html

_F = re.IGNORECASE

URGENCY = [re.compile(p, _F) for p in (
    r"\burgent(ly)?\b",
    r"\bimmediate(ly)?\b",
    r"\bwithin \d+ (minutes?|hours?|days?)\b",
    r"\bact now\b",
    r"\bfinal (notice|warning)\b",
    r"\bunusual activity\b",
    r"\baccount (will be|has been|is) (suspended|locked|closed|disabled|limited)\b",
    r"\bpermanent(ly)? (closure|closed|suspended|deleted)\b",
    r"\bfailure to (act|respond|comply|verify)\b",
    r"\bexpires? (today|soon|in \d+)\b",
)]

CREDENTIALS = [re.compile(p, _F) for p in (
    r"\b(confirm|verify|update|re-?enter|provide|enter|validate|reset|restore|recover|unlock)\b.{0,40}\b"
    r"(password|credentials?|login|card (details|number)|credit card|ssn|social security|"
    r"pin|bank (account|details)|account (details|information))\b",
    r"\b(sign|log)[- ]?in\b.{0,20}\b(to )?(verify|confirm|restore|unlock)\b",
    r"\b(one[- ]time (code|password)|otp|cvv)\b",
)]

GENERIC_GREETING = re.compile(
    r"\bdear (customer|user|member|client|valued \w+|account holder|sir|madam)\b", _F)

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".msi", ".jar", ".iso",
                    ".lnk", ".html", ".htm", ".docm", ".xlsm", ".zip", ".rar", ".img"}


def _matches(patterns, text, limit=5):
    """Collect unique matched phrases (case-insensitive), max `limit`."""
    seen = {}
    for p in patterns:
        for m in p.finditer(text):
            seen.setdefault(m.group(0).lower(), m.group(0))
    return list(seen.values())[:limit]


def _full_text(email: ParsedEmail) -> str:
    body = email.body_text or parse_html(email.body_html)[0]
    return " ".join(f"{email.subject} {body}".split())  # collapse whitespace/newlines


def analyze_content(email: ParsedEmail) -> list:
    text, findings = _full_text(email), []

    urgency = _matches(URGENCY, text)
    if urgency:
        findings.append(Finding(
            "Urgency detected",
            "Email uses urgent or threatening language to pressure the reader into acting quickly.",
            10, "Urgency", urgency))

    creds = _matches(CREDENTIALS, text)
    if creds:
        findings.append(Finding(
            "Credential request",
            "Email appears to ask for login, password, or payment information.",
            15, "Credential request", creds))

    greeting = GENERIC_GREETING.search(text)
    if greeting:
        findings.append(Finding(
            "Generic greeting",
            "Impersonal greeting: real providers usually address you by name.",
            5, "Generic greeting", [greeting.group(0)]))

    brand_hits = brand_text_mentions(text)
    if brand_hits:
        evidence = [f'"{word}" (misspelling of {brand_name(brand)})' for word, brand in brand_hits[:5]]
        findings.append(Finding(
            "Misspelled brand name",
            "The email text refers to a brand using a spelling that doesn't match the real "
            "brand name - a common impersonation trick, even when no link or sender domain is present.",
            25, "Brand name spoofing", evidence))

    risky = [a["filename"] for a in email.attachments
             if os.path.splitext(a["filename"].lower())[1] in RISKY_EXTENSIONS]
    if risky:
        findings.append(Finding(
            "Risky attachment",
            "Attachment type is commonly used to deliver malware.",
            15, "Risky attachment", risky))

    return findings
