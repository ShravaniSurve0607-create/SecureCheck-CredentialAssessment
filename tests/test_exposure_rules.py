from security.exposure_rules import evaluate_security


def test_low_risk():
    policy = {
        "valid": True,
        "errors": [],
        "warnings": []
    }

    result = evaluate_security(
        password_policy=policy,
        password_breached=False,
        exposure_count=0
    )

    assert result["risk"] == "LOW"
    assert len(result["actions"]) > 0


def test_medium_risk_for_weak_password():
    policy = {
        "valid": False,
        "errors": [
            "Password must contain at least 12 characters."
        ],
        "warnings": []
    }

    result = evaluate_security(
        password_policy=policy,
        password_breached=False,
        exposure_count=0
    )

    assert result["risk"] == "MEDIUM"
    assert "Password must contain at least 12 characters." in result["actions"]


def test_high_risk_for_breached_password():
    policy = {
        "valid": True,
        "errors": [],
        "warnings": []
    }

    result = evaluate_security(
        password_policy=policy,
        password_breached=True,
        exposure_count=0
    )

    assert result["risk"] == "HIGH"
    assert "Change this password immediately." in result["actions"]


def test_high_risk_for_exposure():
    policy = {
        "valid": True,
        "errors": [],
        "warnings": []
    }

    result = evaluate_security(
        password_policy=policy,
        password_breached=False,
        exposure_count=2
    )

    assert result["risk"] == "HIGH"
    assert "Review affected credentials and accounts." in result["actions"]