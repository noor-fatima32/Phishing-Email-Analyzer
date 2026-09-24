"""Header analysis: who claims to be sending this, and does it add up?"""
import re

from app.analyzer.email_parser import ParsedEmail
from app.utils.helpers import (BRANDS, FREE_MAIL, Finding, brand_lookalike, brand_name,
                               domain_red_flags, is_legit_domain, related_domains)

_AUTH_FAIL = re.compile(r"\b(spf|dkim|dmarc)=(fail|softfail|permerror)\b", re.I)


def analyze_headers(email: ParsedEmail) -> list:
    findings = []

    # 1. Suspicious sender domain (lookalike, risky TLD, punycode...)
    flags = domain_red_flags(email.from_domain)
    if flags:
        indicator = "Domain impersonation" if brand_lookalike(email.from_domain) else "Suspicious sender domain"
        findings.append(Finding(
            "Suspicious sender domain",
            f"{email.from_domain} " + "; ".join(flags) + ".",
            30, indicator, [email.from_address]))

    # 2. Display name claims a brand, but the address belongs to someone else
    name = email.from_name.lower()
    for brand in BRANDS:
        if brand in name and email.from_domain and not is_legit_domain(email.from_domain, brand):
            findings.append(Finding(
                "Brand impersonation",
                f'Display name "{email.from_name}" claims to be {brand_name(brand)}, '
                f"but the email was sent from {email.from_domain}.",
                30, "Brand impersonation", [f"{email.from_name} <{email.from_address}>"]))
            break

    # 3. Reply-To points somewhere different from the sender
    if (email.reply_to_domain and email.from_domain
            and not related_domains(email.from_domain, email.reply_to_domain)):
        extra = ", a free webmail provider," if email.reply_to_domain in FREE_MAIL else ""
        findings.append(Finding(
            "Reply-To mismatch",
            f"Sender domain ({email.from_domain}) and Reply-To domain "
            f"({email.reply_to_domain}){extra} do not match. Replies would go to a different party.",
            20, "Reply-To mismatch", [f"From: {email.from_address}", f"Reply-To: {email.reply_to_address}"]))

    # 4. Return-Path differs (low weight: legitimate mailing services do this too)
    if (email.return_path_domain and email.from_domain
            and not related_domains(email.from_domain, email.return_path_domain)):
        findings.append(Finding(
            "Return-Path mismatch",
            f"Bounce address domain ({email.return_path_domain}) differs from the sender domain "
            f"({email.from_domain}). Common in spoofed mail, but also in bulk-mail services.",
            5, "Return-Path mismatch", [email.return_path]))

    # 5. Authentication results already recorded by the receiving mail server
    failures = sorted({f"{m.group(1).upper()}={m.group(2).lower()}" for m in _AUTH_FAIL.finditer(email.auth_results)})
    if failures:
        findings.append(Finding(
            "Email authentication failed",
            "The receiving server recorded failed checks: " + ", ".join(failures) +
            ". The sender may not be who they claim to be.",
            15, "Failed email authentication", failures))

    return findings
