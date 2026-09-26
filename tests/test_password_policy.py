from security.password_policy import check_password_policy


def test_strong_password():
    result = check_password_policy("SecurePassword@2026")

    assert result["valid"] is True
    assert result["errors"] == []


def test_short_password():
    result = check_password_policy("Abc@123")

    assert result["valid"] is False
    assert len(result["errors"]) > 0


def test_missing_uppercase():
    result = check_password_policy("securepassword@2026")

    assert result["valid"] is False
    assert any(
        "uppercase" in error.lower()
        for error in result["errors"]
    )


def test_common_password():
    result = check_password_policy("password")

    assert result["valid"] is False
    assert any(
        "common" in error.lower()
        for error in result["errors"]
    )