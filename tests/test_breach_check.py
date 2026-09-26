from security.breach_check import check_password_breach


def test_empty_password():
    result = check_password_breach("")

    assert result["breached"] is False
    assert result["count"] == 0
    assert result["error"] == "Password is empty."


def test_breach_check_returns_result():
    result = check_password_breach("password")

    assert "breached" in result
    assert "count" in result
    assert "error" in result