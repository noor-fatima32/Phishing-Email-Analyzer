"""URL analysis: find every link and check where it really goes."""
import re
from urllib.parse import urlparse

from app.analyzer.email_parser import ParsedEmail
from app.utils.helpers import SHORTENERS, Finding, domain_red_flags, is_ip, parse_html, related_domains

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_DOMAIN_LIKE = re.compile(r"^(www\.)?[\w-]+(\.[\w-]+)*\.[a-z]{2,}(/\S*)?$", re.I)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _displayed_host(text: str) -> str:
    """If the visible link text itself looks like a URL/domain, return its host."""
    t = text.strip()
    if not t or " " in t:
        return ""
    if re.match(r"^https?://", t, re.I):
        return _host(t)
    if _DOMAIN_LIKE.match(t):
        return _host("//" + t)
    return ""


def extract_urls(email: ParsedEmail) -> list:
    """Return [{'url', 'text', 'host'}] from HTML anchors and plain text (deduplicated)."""
    found = {}
    _, links = parse_html(email.body_html)
    for href, text in links:
        if href.lower().startswith(("http://", "https://")):
            found.setdefault(href, {"url": href, "text": text})
    for raw in URL_RE.findall(email.body_text or ""):
        url = raw.rstrip(".,;:!?")
        found.setdefault(url, {"url": url, "text": ""})
    for item in found.values():
        item["host"] = _host(item["url"])
    return list(found.values())


def analyze_urls(email: ParsedEmail):
    """Return (findings, urls). Each finding type appears once, listing affected URLs."""
    urls = extract_urls(email)
    ip_urls, mismatches, bad_domains, shortened = [], [], [], []

    for u in urls:
        host, url = u["host"], u["url"]
        if not host:
            continue
        if is_ip(host):
            ip_urls.append(url)
        if host in SHORTENERS:
            shortened.append(url)

        shown = _displayed_host(u["text"])
        if shown and not related_domains(shown, host):
            mismatches.append(f"shown: {u['text'].strip()}  →  actual: {url}")

        reasons = domain_red_flags(host)
        if urlparse(url).username:  # http://paypal.com@evil.com trick
            reasons.append("contains '@' to disguise the real destination")
        if reasons:
            bad_domains.append(f"{host}: " + "; ".join(reasons))

    findings = []
    if mismatches:
        findings.append(Finding(
            "Suspicious URL",
            "Link text displays one destination, but the link actually goes somewhere else.",
            30, "Deceptive link", mismatches))
    if ip_urls:
        findings.append(Finding(
            "IP-based URL",
            "Link points to a raw IP address instead of a domain name, which legitimate brands rarely do.",
            15, "IP-based URL", ip_urls))
    if bad_domains:
        findings.append(Finding(
            "Suspicious URL domain",
            "A link domain looks like an imitation or uses risky characteristics.",
            30, "Suspicious URL domain", bad_domains))
    if shortened:
        findings.append(Finding(
            "URL shortener",
            "Shortened links hide the real destination.",
            10, "URL shortener", shortened))
    return findings, urls
