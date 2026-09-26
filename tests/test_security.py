import os
import pytest

# Test environment configuration
os.environ.setdefault("MYSQL_HOST", "127.0.0.1")
os.environ.setdefault("MYSQL_USER", "root")
os.environ.setdefault("MYSQL_PASSWORD", "ci-password")
os.environ.setdefault("MYSQL_DATABASE", "credential_assessment")
os.environ.setdefault("SECRET_KEY", "test-secret")

# Import the Flask application and security functions
from app import app, password_policy, check_pwned_password


@pytest.fixture
def client():
    app.config.update(TESTING=True)

    with app.test_client() as c:
        yield c


def csrf(client):
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def test_password_policy():
    result = password_policy("password123")

    assert len(result) > 0

    assert any(
        "common" in error.lower()
        for error in result
    )

    assert password_policy("A-longer-Secure!9") == []


def test_health(client):
    response = client.get("/api/v1/health")

    assert response.status_code in (200, 503)


def test_login_rejects_bad_credentials(client, monkeypatch):
    # Mock the database lookup so this test does not
    # depend on the local MySQL password.
    monkeypatch.setattr(
        "app.fetch_one",
        lambda *args, **kwargs: None
    )

    client.get("/login")

    response = client.post(
        "/login",
        data={
            "_csrf": csrf(client),
            "email": "nobody@example.invalid",
            "password": "bad"
        },
        follow_redirects=True
    )

    assert b"Invalid email or password" in response.data


def test_exposure_hash_uses_k_anonymity(monkeypatch):

    class Response:
        text = "ABCDEF1234:2\n"

        def raise_for_status(self):
            pass

    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return Response()

    monkeypatch.setattr(
        "app.requests.get",
        fake_get
    )

    result = check_pwned_password(
        "correct horse battery staple"
    )

    prefix = seen["url"].rstrip("/").split("/")[-1]

    # Only a 5-character hash prefix should be sent
    assert len(prefix) == 5
    assert prefix.isalnum()

    # Verify the correct Pwned Passwords API endpoint
    assert seen["url"].startswith(
        "https://api.pwnedpasswords.com/range/"
    )

    assert "match_count" in result