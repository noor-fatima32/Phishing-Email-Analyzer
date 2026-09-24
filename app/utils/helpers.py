"""Shared helpers: Finding model, brand/domain checks, HTML parsing."""
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from ipaddress import ip_address


@dataclass
class Finding:
    """One thing an analyzer noticed. The risk engine sums the weights."""
    title: str
    detail: str
    weight: int
    indicator: str
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return self.__dict__.copy()


# Brand -> domains that legitimately belong to it (small demo list).
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "docusign": ["docusign.com", "docusign.net"],
}

BRAND_NAMES = {"paypal": "PayPal", "linkedin": "LinkedIn", "docusign": "DocuSign",
               "fedex": "FedEx", "dhl": "DHL"}


def brand_name(brand: str) -> str:
    """Proper display casing: paypal -> PayPal."""
    return BRAND_NAMES.get(brand, brand.title())


FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "aol.com"}
RISKY_TLDS = {"zip", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "icu", "rest", "loan", "work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}

# Common character swaps used in lookalike domains: paypa1 -> paypal
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance - catches inserted/dropped/swapped letters
    (instagraam <-> instagram, paypall <-> paypal, mircosoft <-> microsoft)."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _typo_distance_ok(token: str, brand: str) -> bool:
    """Is `token` within a plausible typo-distance of `brand`? Scaled by brand length
    so short brands (dhl, dmc) don't false-positive on unrelated short words."""
    if not token or abs(len(token) - len(brand)) > 2:
        return False
    threshold = 1 if len(brand) <= 5 else 2
    dist = _edit_distance(token, brand)
    return 0 < dist <= threshold


def is_ip(host: str) -> bool:
    try:
        ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_legit_domain(domain: str, brand: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in BRANDS[brand])


def related_domains(a: str, b: str) -> bool:
    """True if domains are the same or parent/child (mail.x.com vs x.com)."""
    a, b = a.removeprefix("www."), b.removeprefix("www.")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def brand_lookalike(domain: str):
    """Return (brand, used_substitution) if `domain` imitates a brand it doesn't own."""
    d = domain.lower()
    raw_tokens = re.split(r"[.\-_]", d)
    norm_tokens = re.split(r"[.\-_]", d.translate(_LEET).replace("rn", "m").replace("vv", "w"))
    for brand in BRANDS:
        if is_legit_domain(d, brand):
            continue
        if any(t == brand or t.startswith(brand) for t in raw_tokens):
            return brand, False
        if any(t == brand or t.startswith(brand) for t in norm_tokens):
            return brand, True
    # Fuzzy pass: catches typosquats that aren't simple leet substitutions or prefixes -
    # doubled letters (instagraam), dropped letters (instagrm), swapped letters (paypla).
    for brand in BRANDS:
        if is_legit_domain(d, brand):
            continue
        if any(_typo_distance_ok(t, brand) for t in raw_tokens):
            return brand, True
    return None


# Brands short enough (<=4 chars) that fuzzy word matching against free text would be too
# noisy (too many unrelated short words sit within edit-distance 1). Skipped for the
# text-level check below; domain-level typosquat checking is unaffected.
_TEXT_TYPO_MIN_BRAND_LEN = 5


_COMMON_SUFFIXES = ("s", "es", "ed", "er", "ers", "ing", "y")


def brand_text_mentions(text: str):
    """Find words in free-form subject/body text that are near-miss misspellings of a
    known brand name (e.g. 'Instagraam' in 'The Instagraam Team'), as opposed to a
    domain. Returns a list of (word_as_written, brand) tuples for correctly-cased
    display, skipping correctly spelled brand names, ordinary brand+suffix words
    (Googler, Googling, Apples), and very short brand names (too many unrelated short
    words would false-positive)."""
    seen, hits = set(), []
    for word in re.findall(r"[A-Za-z]+", text):
        lw = word.lower()
        if lw in seen:
            continue
        for brand in BRANDS:
            if len(brand) < _TEXT_TYPO_MIN_BRAND_LEN or lw == brand:
                continue
            if lw.startswith(brand) and lw[len(brand):] in _COMMON_SUFFIXES:
                continue  # ordinary word built on the correctly spelled brand
            if _typo_distance_ok(lw, brand):
                seen.add(lw)
                hits.append((word, brand))
                break
    return hits


def domain_red_flags(domain: str) -> list:
    """Human-readable reasons a domain looks suspicious (empty list = nothing found)."""
    flags = []
    if not domain or is_ip(domain):
        return flags
    hit = brand_lookalike(domain)
    if hit:
        brand, substituted = hit
        name = brand_name(brand)
        flags.append(f"imitates {name} using look-alike characters" if substituted
                     else f"contains the {name} name but is not a {name} domain")
    tld = domain.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flags.append(f"uses a high-abuse TLD (.{tld})")
    if "xn--" in domain:
        flags.append("contains punycode (possible homograph attack)")
    if domain.count(".") >= 4:
        flags.append("has an unusually long chain of subdomains")
    return flags


class _HTMLExtractor(HTMLParser):
    """Collects visible text and (href, link text) pairs."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links = [], []
        self._href, self._buf, self._skip = None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href, self._buf = dict(attrs).get("href"), []

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def parse_html(html: str):
    """Return (visible_text, [(href, link_text), ...])."""
    p = _HTMLExtractor()
    p.feed(html or "")
    return " ".join(" ".join(p.text).split()), p.links
