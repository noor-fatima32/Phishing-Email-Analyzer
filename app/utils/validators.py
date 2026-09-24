"""Input validation for the web layer. Raises ValueError with a user-facing message."""
import os

MAX_BYTES = 2 * 1024 * 1024          # 2 MB is plenty for an email without huge attachments
ALLOWED_EXTENSIONS = {".eml", ".txt"}


def validate_text(text) -> str:
    """Validate pasted email text and return it."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Paste an email or upload a file first.")
    if len(text.encode("utf-8", errors="ignore")) > MAX_BYTES:
        raise ValueError("Email is larger than 2 MB. Paste only the headers and body.")
    return text


def validate_upload(filename: str, data: bytes) -> bytes:
    """Validate an uploaded file's name and size and return its bytes."""
    ext = os.path.splitext((filename or "").lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .eml or .txt files are supported.")
    if not data or not data.strip():
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_BYTES:
        raise ValueError("File is larger than 2 MB.")
    return data
