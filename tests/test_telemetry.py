from flask import Flask

from security.telemetry import (
    start_timer,
    get_request_time,
    request_info
)


def test_request_timer():
    app = Flask(__name__)

    with app.test_request_context("/test", method="GET"):
        start_timer()

        elapsed = get_request_time()

        assert isinstance(elapsed, float)
        assert elapsed >= 0


def test_request_info():
    app = Flask(__name__)

    with app.test_request_context(
        "/security-check",
        method="POST"
    ):
        info = request_info()

        assert info["method"] == "POST"
        assert info["path"] == "/security-check"
        assert "remote_addr" in info