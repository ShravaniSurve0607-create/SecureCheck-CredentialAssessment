import re


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou"
}


def check_password_policy(password):
    """
    Check whether a password satisfies the application's
    security policy.
    """

    errors = []
    warnings = []

    if not password:
        return {
            "valid": False,
            "errors": ["Password cannot be empty."],
            "warnings": warnings
        }

    if len(password) < 12:
        errors.append(
            "Password must contain at least 12 characters."
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        errors.append(
            "Password must contain at least one number."
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append(
            "Password must contain at least one special character."
        )

    if password.lower() in COMMON_PASSWORDS:
        errors.append(
            "This password is too common."
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }