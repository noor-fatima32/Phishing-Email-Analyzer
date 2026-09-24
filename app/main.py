"""Command-line entry point.

Usage:
    python -m app.main samples/suspicious_email.eml
    python -m app.main samples/suspicious_email.eml --json
    python -m app.main --web            # web UI at http://127.0.0.1:5000
    cat email.eml | python -m app.main
"""
import argparse
import json
import os
import sys

from pathlib import Path

from app.analyzer.risk_engine import analyze_email
from app.utils.validators import MAX_BYTES, validate_text, validate_upload

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = {
    "suspicious": "suspicious_email.eml",
    "parcel": "parcel_notice.eml",
    "invoice": "invoice_attachment.eml",
    "safe": "safe_email.eml",
}

WIDTH = 64
COLORS = {"LOW": "\033[92m", "MEDIUM": "\033[93m", "HIGH": "\033[91m"}
RESET = "\033[0m"


def _truncate(text: str, limit: int = 100) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def format_report(r: dict, color: bool = False) -> str:
    """Render an analyze_email() result as a readable text report."""
    lines = []

    def section(title):
        lines.extend(["", title, "─" * WIDTH])

    level = r["risk_level"]
    level_txt = f"{COLORS[level]}{level}{RESET}" if color else level

    lines += ["PHISHING EMAIL ANALYSIS", "═" * WIDTH, "",
              f"Risk Level: {level_txt}", f"Risk Score: {r['risk_score']}/100"]

    if r.get("notice"):
        lines += ["", f"ℹ {r['notice']}"]

    e = r["email"]
    section("EMAIL INFORMATION")
    lines += [f"From:       {e['from']}",
              f"Reply-To:   {e['reply_to'] or '-'}",
              f"Subject:    {e['subject'] or '-'}",
              f"Date:       {e['date'] or '-'}"]
    if e["attachments"]:
        lines.append(f"Attachments: {', '.join(e['attachments'])}")

    section("FINDINGS")
    if not r["findings"]:
        lines.append("No suspicious findings.")
    for f in r["findings"]:
        lines += ["", f"⚠ {f['title']}  (+{f['weight']})", f"  {f['detail']}"]
        lines += [f"    • {_truncate(ev)}" for ev in f["evidence"][:3]]

    section("URLS FOUND")
    lines += [_truncate(u["url"]) for u in r["urls"]] or ["None"]

    section("SUSPICIOUS INDICATORS")
    lines += [f"[!] {i}" for i in r["indicators"]] or ["None"]

    section("VERDICT")
    lines += ["", r["verdict"], "", "Recommendation:", r["recommendation"], ""]
    return "\n".join(lines)


def create_app():
    """Flask app factory (Flask is imported lazily so the CLI works without it)."""
    from flask import Flask, jsonify, render_template, request

    app = Flask(__name__, template_folder="templates", static_folder=str(ROOT / "static"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES + 64 * 1024

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; frame-ancestors 'none'")
        return resp

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/sample/<name>")
    def sample(name):
        filename = SAMPLES.get(name)  # whitelist: no user-controlled paths
        if not filename:
            return jsonify(error="Unknown sample."), 404
        return jsonify(email=(ROOT / "samples" / filename).read_text(encoding="utf-8"))

    @app.post("/analyze")
    def analyze():
        try:
            if "file" in request.files:                      # curl -F file=@mail.eml
                upload = request.files["file"]
                raw = validate_upload(upload.filename, upload.read(MAX_BYTES + 1))
            else:                                            # browser UI sends JSON
                raw = validate_text((request.get_json(silent=True) or {}).get("email"))
            return jsonify(analyze_email(raw))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="Email is larger than 2 MB."), 413

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(prog="phishing-analyzer",
                                     description="Lightweight rule-based phishing email analyzer.")
    parser.add_argument("file", nargs="?", help="path to a .eml file (omit to read from stdin)")
    parser.add_argument("--json", action="store_true", help="output raw JSON instead of a report")
    parser.add_argument("--web", action="store_true", help="start the web UI instead of the CLI")
    parser.add_argument("--port", type=int, default=5000, help="web UI port (default 5000)")
    args = parser.parse_args(argv)

    if args.web:
        print(f"Web UI running at http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
        create_app().run(host="127.0.0.1", port=args.port, debug=False)
        return

    if hasattr(sys.stdout, "reconfigure"):          # avoid Windows console encoding errors
        sys.stdout.reconfigure(encoding="utf-8")

    try:
        raw = open(args.file, "rb").read() if args.file else sys.stdin.buffer.read()
    except OSError as exc:
        sys.exit(f"Error: could not read input: {exc}")

    try:
        result = analyze_email(raw)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(format_report(result, color=use_color))


if __name__ == "__main__":
    main()
