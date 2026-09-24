import io

import pytest

from app.main import create_app
from app.utils.validators import validate_text, validate_upload


@pytest.fixture()
def client():
    return create_app().test_client()


def test_index_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Phishing email analyzer" in r.data
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_static_assets_served(client):
    assert client.get("/static/css/style.css").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200


@pytest.mark.parametrize("name", ["suspicious", "parcel", "invoice", "safe"])
def test_sample_endpoint(client, name):
    r = client.get(f"/sample/{name}")
    assert r.status_code == 200 and "From:" in r.get_json()["email"]


def test_unknown_sample_and_path_traversal_rejected(client):
    assert client.get("/sample/nope").status_code == 404
    assert client.get("/sample/..%2Fapp%2Fmain.py").status_code == 404


def test_analyze_json_high_risk(client):
    email = client.get("/sample/suspicious").get_json()["email"]
    r = client.post("/analyze", json={"email": email})
    d = r.get_json()
    assert r.status_code == 200 and d["risk_level"] == "HIGH" and d["risk_score"] == 100


def test_analyze_json_low_risk(client):
    email = client.get("/sample/safe").get_json()["email"]
    assert client.post("/analyze", json={"email": email}).get_json()["risk_level"] == "LOW"


def test_analyze_file_upload(client):
    data = open("samples/suspicious_email.eml", "rb").read()
    r = client.post("/analyze", data={"file": (io.BytesIO(data), "mail.eml")},
                    content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json()["risk_level"] == "HIGH"


@pytest.mark.parametrize("payload", [{}, {"email": ""}, {"email": "   "}, {"email": 123}])
def test_bad_input_returns_400_with_message(client, payload):
    r = client.post("/analyze", json=payload)
    assert r.status_code == 400 and r.get_json()["error"]


def test_plain_typed_text_is_analyzed_not_rejected(client):
    """Someone just types an email with no headers - should get a 200 with a notice,
    not a 400 rejection."""
    r = client.post("/analyze", json={"email": "not an email, just plain text, urgent action required now"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["has_headers"] is False
    assert data["notice"]


def test_upload_wrong_extension_rejected(client):
    r = client.post("/analyze", data={"file": (io.BytesIO(b"From: a@b.com\n\nhi"), "evil.exe")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and ".eml" in r.get_json()["error"]


def test_oversized_input_rejected(client):
    r = client.post("/analyze", json={"email": "From: a@b.com\n\n" + "x" * (3 * 1024 * 1024)})
    assert r.status_code in (400, 413)


def test_validators_directly():
    with pytest.raises(ValueError):
        validate_text("")
    with pytest.raises(ValueError):
        validate_upload("a.pdf", b"data")
    assert validate_text("From: a@b.com") == "From: a@b.com"
