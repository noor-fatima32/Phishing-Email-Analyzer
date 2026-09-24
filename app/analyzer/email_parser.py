"""Email parser: turns raw .eml / pasted email text into a ParsedEmail object.

Uses only the Python standard library. All later analyzers (headers, URLs,
content) work from the ParsedEmail this module produces.
"""
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
import re

# Matches an email address appearing anywhere in plain typed/pasted text (not a header).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass
class ParsedEmail:
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    received: list = field(default_factory=list)   # newest hop first
    auth_results: str = ""                         # raw Authentication-Results header
    body_text: str = ""
    body_html: str = ""
    attachments: list = field(default_factory=list)  # [{"filename", "content_type"}]
    has_headers: bool = True   # False when the input was plain typed/pasted text, no email headers

    def to_dict(self):
        return self.__dict__.copy()


def get_domain(address: str) -> str:
    """Return the lowercase domain part of an email address ('' if none)."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().strip(">").lower()


def _split_address(header_value: str):
    """'"PayPal" <a@b.com>' -> ('PayPal', 'a@b.com')"""
    name, addr = parseaddr(header_value or "")
    return name.strip(), addr.strip().lower()


def _get_part_text(msg, kind: str) -> str:
    """Safely extract the 'plain' or 'html' body; never crash on odd encodings."""
    try:
        part = msg.get_body(preferencelist=(kind,))
        return part.get_content() if part else ""
    except Exception:
        return ""


def parse_email(raw) -> ParsedEmail:
    """Parse raw email (str or bytes) into a ParsedEmail.

    Accepts three kinds of input:
      1. A full raw email with headers (.eml source, pasted with headers).
      2. Plain typed/pasted text with no headers at all (e.g. someone just types
         or pastes the message body they received) - analyzed as body text only,
         with `has_headers=False` so header-based checks are skipped.

    Raises ValueError only if the input is empty.
    """
    if raw is None or not raw.strip():
        raise ValueError("Email input is empty.")

    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        text = raw.decode("utf-8", errors="replace")
    else:
        msg = Parser(policy=policy.default).parsestr(raw)
        text = raw

    # A real email should have at least one of these headers. If none are present,
    # this is plain typed text (no headers) - treat the whole input as the message body
    # instead of rejecting it, so "just type/paste an email" always works. If a real
    # email address appears anywhere in that text (e.g. someone just pastes a sender
    # address to check, or the address is mentioned in a copy-pasted message), pick it
    # up as the sender so domain/brand-impersonation checks still run on it.
    if not any(msg.get(h) for h in ("From", "Subject", "Received", "To", "Date")):
        stripped = text.strip()
        found = _EMAIL_RE.search(stripped)
        from_addr = found.group(0).lower() if found else ""
        return ParsedEmail(
            from_address=from_addr,
            from_domain=get_domain(from_addr),
            body_text=stripped,
            has_headers=False,
        )

    from_name, from_addr = _split_address(str(msg.get("From", "")))
    _, reply_addr = _split_address(str(msg.get("Reply-To", "")))
    _, return_addr = _split_address(str(msg.get("Return-Path", "")))

    attachments = []
    for part in msg.iter_attachments():
        attachments.append({
            "filename": part.get_filename() or "(unnamed)",
            "content_type": part.get_content_type(),
        })

    return ParsedEmail(
        from_name=from_name,
        from_address=from_addr,
        from_domain=get_domain(from_addr),
        reply_to_address=reply_addr,
        reply_to_domain=get_domain(reply_addr),
        return_path=return_addr,
        return_path_domain=get_domain(return_addr),
        to=str(msg.get("To", "")),
        subject=str(msg.get("Subject", "")).strip(),
        date=str(msg.get("Date", "")),
        received=[str(r) for r in msg.get_all("Received", [])],
        auth_results=str(msg.get("Authentication-Results", "")),
        body_text=_get_part_text(msg, "plain"),
        body_html=_get_part_text(msg, "html"),
        attachments=attachments,
    )


if __name__ == "__main__":
    # Quick check:  python -m app.analyzer.email_parser samples/suspicious_email.eml
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("Usage: python -m app.analyzer.email_parser <file.eml>")
    with open(sys.argv[1], "rb") as f:
        print(json.dumps(parse_email(f.read()).to_dict(), indent=2))
