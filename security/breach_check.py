import hashlib
import requests

HIBP_URL = "https://api.pwnedpasswords.com/range/"


def check_password_breach(password):
    """
    Check whether a password has appeared in known breaches.

    The complete password is never sent to the API.
    Only the first 5 characters of its SHA-1 hash are sent.
    """

    if not password:
        return {
            "breached": False,
            "count": 0,
            "error": "Password is empty."
        }

    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            HIBP_URL + prefix,
            headers={
                "User-Agent": "CredentialAssessment-SecurityCheck"
            },
            timeout=5
        )

        response.raise_for_status()

    except requests.RequestException as error:
        return {
            "breached": False,
            "count": 0,
            "error": f"Breach service unavailable: {error}"
        }

    for line in response.text.splitlines():

        parts = line.split(":")

        if len(parts) != 2:
            continue

        returned_suffix = parts[0].strip().upper()
        count = int(parts[1].strip())

        if returned_suffix == suffix:
            return {
                "breached": True,
                "count": count,
                "error": None
            }

    return {
        "breached": False,
        "count": 0,
        "error": None
    }