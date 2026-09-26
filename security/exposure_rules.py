def evaluate_security(password_policy, password_breached, exposure_count=0):
    """
    Evaluate overall credential security risk.

    Parameters:
        password_policy: Result from check_password_policy()
        password_breached: True if password was found in a breach
        exposure_count: Number of known exposure records

    Returns:
        Dictionary containing risk level and recommended actions.
    """

    risk = "LOW"
    actions = []

    # Breached password is a high-risk condition
    if password_breached:
        risk = "HIGH"
        actions.append(
            "Change this password immediately."
        )

    # Password policy violations
    if not password_policy["valid"]:
        if risk != "HIGH":
            risk = "MEDIUM"

        actions.extend(
            password_policy["errors"]
        )

    # Known credential exposure
    if exposure_count > 0:
        risk = "HIGH"
        actions.append(
            "Review affected credentials and accounts."
        )

    # If no issues were found
    if not actions:
        actions.append(
            "No immediate security action is required."
        )

    return {
        "risk": risk,
        "actions": actions
    }