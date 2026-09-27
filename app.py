import hashlib
import hmac
import os
import re
import secrets
import time
from functools import wraps

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_database_connection, initialize_database

# Person 2 security modules
from security.password_policy import check_password_policy
from security.breach_check import check_password_breach
from security.exposure_rules import evaluate_security
from security.audit import log_event


app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "dev-only-change-me",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE",
        "0",
    ) == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)


# =========================================================
# Constants
# =========================================================

HIBP_URL = "https://api.pwnedpasswords.com/range/"
HIBP_USER_AGENT = "SecureCheck-Credential-Assessment/1.0"

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
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "abc123",
    "monkey",
    "dragon",
    "football",
    "login",
    "secret",
    "changeme",
}

# Corrected email validation pattern
EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# CSRF Protection
# =========================================================

def get_csrf_token():
    """
    Create a CSRF token for the current session if one
    does not already exist.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


def valid_csrf(token):
    """
    Validate the supplied CSRF token.
    """
    expected = session.get("csrf_token")

    if not token or not expected:
        return False

    return hmac.compare_digest(
        str(token),
        str(expected),
    )


@app.context_processor
def inject_csrf_token():
    """
    Make csrf_token available to every template.
    """
    return {
        "csrf_token": get_csrf_token()
    }


# =========================================================
# Authentication Helpers
# =========================================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash(
                "Please log in to continue.",
                "warning",
            )
            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):

        if not session.get("user_id"):
            flash(
                "Please log in first.",
                "warning",
            )
            return redirect(
                url_for("login")
            )

        if session.get("role") != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


# =========================================================
# Compatibility Functions
# =========================================================

def password_policy(password):
    """
    Compatibility wrapper used by tests and older application
    code.

    The actual policy is implemented in
    security/password_policy.py.
    """
    result = check_password_policy(password)

    return result.get(
        "errors",
        [],
    )


def check_pwned_password(password):
    """
    Compatibility wrapper for the breach checker.

    Only the first five characters of the SHA-1 hash are sent
    to the external breach service.
    """
    result = check_password_breach(password)

    return {
        "breached": result.get(
            "breached",
            False,
        ),
        "match_count": result.get(
            "count",
            0,
        ),
        "error": result.get(
            "error"
        ),
    }


# =========================================================
# Database Helpers
# =========================================================

def fetch_one(query, values=()):
    conn = get_database_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute(query, values)
        return cur.fetchone()

    finally:
        cur.close()
        conn.close()


def fetch_all(query, values=()):
    conn = get_database_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute(query, values)
        return cur.fetchall()

    finally:
        cur.close()
        conn.close()


# =========================================================
# Application Initialization
# =========================================================

def initialize_app():
    initialize_database()


# =========================================================
# Before Request
# =========================================================

@app.before_request
def before_request():

    request._securecheck_start = time.perf_counter()

    # Generate CSRF token for every session.
    get_csrf_token()

    if request.method == "POST":

        token = (
            request.form.get("_csrf")
            or request.headers.get("X-CSRF-Token")
        )

        if request.endpoint not in {"static"}:

            if not valid_csrf(token):
                abort(
                    400,
                    description="Invalid CSRF token.",
                )


# =========================================================
# After Request / Telemetry
# =========================================================

@app.after_request
def after_request(response):

    started = getattr(
        request,
        "_securecheck_start",
        None,
    )

    duration_ms = (
        round(
            (time.perf_counter() - started) * 1000,
            2,
        )
        if started
        else None
    )

    try:

        conn = get_database_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO request_metrics
            (
                method,
                path,
                status_code,
                response_time_ms,
                error_message
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                request.method,
                request.path,
                response.status_code,
                duration_ms,
                None,
            ),
        )

        conn.commit()

        cur.close()
        conn.close()

    except Exception:
        # Telemetry failure must not break the application.
        pass

    return response


# =========================================================
# Home
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# Register
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"],
)
def register():

    if request.method == "GET":

        return render_template(
            "register.html"
        )

    name = request.form.get(
        "name",
        "",
    ).strip()

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    password = request.form.get(
        "password",
        "",
    )

    if not name:

        flash(
            "Name is required.",
            "danger",
        )

        return render_template(
            "register.html"
        )

    if not EMAIL_RE.match(email):

        flash(
            "Please enter a valid email address.",
            "danger",
        )

        return render_template(
            "register.html"
        )

    policy = check_password_policy(
        password
    )

    if not policy["valid"]:

        for error in policy["errors"]:

            flash(
                error,
                "danger",
            )

        return render_template(
            "register.html"
        )

    conn = get_database_connection()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            SELECT id
            FROM users
            WHERE email = %s
            """,
            (email,),
        )

        existing = cur.fetchone()

        if existing:

            flash(
                "An account with this email already exists.",
                "danger",
            )

            return render_template(
                "register.html"
            )

        password_hash = generate_password_hash(
            password
        )

        cur.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password,
                role
            )
            VALUES (%s, %s, %s, 'user')
            """,
            (
                name,
                email,
                password_hash,
            ),
        )

        user_id = cur.lastrowid

        conn.commit()

        try:

            log_event(
                conn,
                target_type="USER",
                target_id=user_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get(
                    "User-Agent"
                ),
                metadata={
                    "action": "REGISTER"
                },
            )

        except Exception:
            pass

        flash(
            "Registration successful. Please log in.",
            "success",
        )

        return redirect(
            url_for("login")
        )

    except Exception:

        conn.rollback()

        flash(
            "Registration failed. Please try again.",
            "danger",
        )

        return render_template(
            "register.html"
        )

    finally:

        cur.close()
        conn.close()


# =========================================================
# Login
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    password = request.form.get(
        "password",
        "",
    )

    user = fetch_one(
        """
        SELECT
            id,
            name,
            email,
            password,
            role
        FROM users
        WHERE email = %s
        """,
        (email,),
    )

    if not user or not check_password_hash(
        user["password"],
        password,
    ):

        # Record failed authentication without storing the password.
        try:

            conn = get_database_connection()

            try:

                log_event(
                    conn,
                    target_type="AUTHENTICATION",
                    target_id=None,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get(
                        "User-Agent"
                    ),
                    metadata={
                        "action": "LOGIN",
                        "status": "failure",
                    },
                )

            finally:

                conn.close()

        except Exception:
            pass

        flash(
            "Invalid email or password",
            "danger",
        )

        return render_template(
            "login.html"
        )

    session.clear()

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["role"] = user["role"]

    # New session gets a fresh CSRF token.
    session["csrf_token"] = secrets.token_hex(32)

    try:

        conn = get_database_connection()

        try:

            log_event(
                conn,
                target_type="AUTHENTICATION",
                target_id=user["id"],
                ip_address=request.remote_addr,
                user_agent=request.headers.get(
                    "User-Agent"
                ),
                metadata={
                    "action": "LOGIN",
                    "status": "success",
                },
            )

        finally:

            conn.close()

    except Exception:
        pass

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# Logout
# =========================================================

@app.route("/logout")
def logout():

    user_id = session.get(
        "user_id"
    )

    if user_id:

        try:

            conn = get_database_connection()

            try:

                log_event(
                    conn,
                    target_type="AUTHENTICATION",
                    target_id=user_id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get(
                        "User-Agent"
                    ),
                    metadata={
                        "action": "LOGOUT"
                    },
                )

            finally:

                conn.close()

        except Exception:
            pass

    session.clear()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# Dashboard
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]

    results = fetch_all(
        """
        SELECT
            score,
            readiness_level,
            created_at
        FROM assessment_results
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (user_id,),
    )

    exposures = fetch_all(
        """
        SELECT
            email_checked,
            status,
            checked_at
        FROM exposure_checks
        WHERE user_id = %s
        ORDER BY checked_at DESC
        LIMIT 10
        """,
        (user_id,),
    )

    return render_template(
        "dashboard.html",
        results=results,
        exposures=exposures,
    )


# =========================================================
# Assessment
# =========================================================

@app.route(
    "/assessment",
    methods=["GET", "POST"],
)
@login_required
def assessment():

    if request.method == "GET":

        return render_template(
            "assessment.html"
        )

    score = 0

    for number in range(1, 6):

        answer = request.form.get(
            f"q{number}"
        )

        if answer == "yes":
            score += 20

        elif answer == "partial":
            score += 10

    if score >= 80:
        level = "High"

    elif score >= 50:
        level = "Medium"

    else:
        level = "Low"

    conn = get_database_connection()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            INSERT INTO assessment_results
            (
                user_id,
                score,
                readiness_level
            )
            VALUES (%s, %s, %s)
            """,
            (
                session["user_id"],
                score,
                level,
            ),
        )

        conn.commit()

        try:

            log_event(
                conn,
                target_type="ASSESSMENT",
                target_id=cur.lastrowid,
                ip_address=request.remote_addr,
                user_agent=request.headers.get(
                    "User-Agent"
                ),
                metadata={
                    "action": "ASSESSMENT",
                    "score": score,
                    "readiness_level": level,
                },
            )

        except Exception:
            pass

    finally:

        cur.close()
        conn.close()

    return render_template(
        "result.html",
        score=score,
        level=level,
    )


# =========================================================
# Assessment History
# =========================================================

@app.route("/history")
@login_required
def history():

    results = fetch_all(
        """
        SELECT
            score,
            readiness_level,
            created_at
        FROM assessment_results
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    )

    return render_template(
        "history.html",
        results=results,
    )


# =========================================================
# Profile
# =========================================================

@app.route(
    "/profile",
    methods=["GET", "POST"],
)
@login_required
def profile():

    if request.method == "GET":

        return render_template(
            "profile.html"
        )

    name = request.form.get(
        "name",
        "",
    ).strip()

    if not name:

        flash(
            "Name cannot be empty.",
            "danger",
        )

        return render_template(
            "profile.html"
        )

    conn = get_database_connection()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            UPDATE users
            SET name = %s
            WHERE id = %s
            """,
            (
                name,
                session["user_id"],
            ),
        )

        conn.commit()

        session["user_name"] = name

        flash(
            "Profile updated successfully.",
            "success",
        )

    finally:

        cur.close()
        conn.close()

    return render_template(
        "profile.html"
    )


# =========================================================
# Email Exposure Check
# =========================================================

@app.route(
    "/exposure",
    methods=["GET", "POST"],
)
@login_required
def exposure():

    result = None

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        if not EMAIL_RE.match(email):

            flash(
                "Please enter a valid email address.",
                "danger",
            )

            return render_template(
                "exposure.html",
                result=None,
            )

        # Local/demo exposure check.
        status = "Not Exposed"

        conn = get_database_connection()
        cur = conn.cursor()

        try:

            cur.execute(
                """
                INSERT INTO exposure_checks
                (
                    user_id,
                    email_checked,
                    status
                )
                VALUES (%s, %s, %s)
                """,
                (
                    session["user_id"],
                    email,
                    status,
                ),
            )

            conn.commit()

            result = {
                "email": email,
                "status": status,
            }

            try:

                log_event(
                    conn,
                    target_type="EXPOSURE_CHECK",
                    target_id=cur.lastrowid,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get(
                        "User-Agent"
                    ),
                    metadata={
                        "action": "EXPOSURE_CHECK",
                        "status": status,
                    },
                )

            except Exception:
                pass

        finally:

            cur.close()
            conn.close()

    return render_template(
        "exposure.html",
        result=result,
    )


# =========================================================
# Credential Exposure / HIBP
# =========================================================

@app.route(
    "/credential-exposure",
    methods=["GET", "POST"],
)
@login_required
def credential_exposure():

    result = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            "",
        )

        if not password:

            flash(
                "Password is required.",
                "danger",
            )

            return render_template(
                "credential_exposure.html",
                result=None,
            )

        # SHA-1 is calculated locally.
        # Only its 5-character prefix is used by the
        # breach-check service.
        sha1_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        prefix = sha1_hash[:5]

        breach_result = check_password_breach(
            password
        )

        exposed = breach_result.get(
            "breached",
            False,
        )

        match_count = breach_result.get(
            "count",
            0,
        )

        result = {
            "exposed": exposed,
            "match_count": match_count,
            "prefix": prefix,
            "error": breach_result.get(
                "error"
            ),
        }

        conn = get_database_connection()
        cur = conn.cursor()

        try:

            cur.execute(
                """
                INSERT INTO credential_exposure_checks
                (
                    user_id,
                    sha1_prefix,
                    exposed,
                    match_count
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    session["user_id"],
                    prefix,
                    exposed,
                    match_count,
                ),
            )

            conn.commit()

            try:

                log_event(
                    conn,
                    target_type="CREDENTIAL_EXPOSURE",
                    target_id=cur.lastrowid,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get(
                        "User-Agent"
                    ),
                    metadata={
                        "action": "CREDENTIAL_EXPOSURE",
                        "exposed": exposed,
                        "match_count": match_count,
                    },
                )

            except Exception:
                pass

        finally:

            cur.close()
            conn.close()

    return render_template(
        "credential_exposure.html",
        result=result,
    )


# =========================================================
# Password Policy
# =========================================================

@app.route(
    "/password-policy",
    methods=["GET", "POST"],
)
@login_required
def password_policy_page():

    result = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            "",
        )

        result = check_password_policy(
            password
        )

        result["violations"] = result.get(
            "errors",
            [],
        )

    return render_template(
        "password_policy.html",
        result=result,
    )


# =========================================================
# Recommendations
# =========================================================

@app.route("/recommendations")
@login_required
def recommendations():

    return render_template(
        "recommendations.html"
    )


# =========================================================
# Security Awareness Lessons
# =========================================================

@app.route("/awareness")
@login_required
def awareness():

    lessons = [
        {
            "title": "Password hygiene",
            "description": (
                "Use a unique password for every important account. "
                "Prefer a password manager instead of reusing passwords."
            ),
        },
        {
            "title": "Phishing awareness",
            "description": (
                "Verify unexpected links, attachments and login requests "
                "before entering credentials."
            ),
        },
        {
            "title": "Multi-factor authentication",
            "description": (
                "Use MFA for sensitive accounts. Prefer phishing-resistant "
                "methods such as passkeys or security keys where supported."
            ),
        },
        {
            "title": "Credential exposure",
            "description": (
                "A breached password should be considered compromised "
                "and replaced with a new unique credential."
            ),
        },
        {
            "title": "Safe recovery",
            "description": (
                "Keep recovery methods current and protect recovery codes "
                "with the same care as primary credentials."
            ),
        },
    ]

    return render_template(
        "awareness.html",
        lessons=lessons,
    )


# =========================================================
# Password Reset Guidance
# =========================================================

@app.route("/reset-guidance")
@login_required
def reset_guidance():

    steps = [
        "Confirm that the password reset request was initiated by you.",
        "Use the official website or application instead of a link from an unexpected message.",
        "Create a new password that satisfies the SecureCheck password policy.",
        "Do not reuse a breached or previously used password.",
        "Sign out of other sessions when the service provides that option.",
        "Review account recovery methods and enable MFA.",
    ]

    return render_template(
        "reset_guidance.html",
        steps=steps,
    )


# =========================================================
# Passwordless Readiness Assessment
# =========================================================

@app.route(
    "/passwordless-readiness",
    methods=["GET", "POST"],
)
@login_required
def passwordless_readiness():

    result = None

    questions = [
        (
            "mfa",
            "Is multi-factor authentication enabled for your important accounts?",
        ),
        (
            "phishing_resistant",
            "Do you use a phishing-resistant authenticator such as a passkey or security key?",
        ),
        (
            "recovery",
            "Are your account recovery methods current and protected?",
        ),
        (
            "device",
            "Do your main devices support secure biometric or device-based authentication?",
        ),
        (
            "password_manager",
            "Do you use a password manager for accounts that still require passwords?",
        ),
    ]

    if request.method == "POST":

        score = 0

        for key, _ in questions:

            if request.form.get(key) == "yes":
                score += 20

        if score >= 80:
            level = "Ready"

        elif score >= 50:
            level = "Partially Ready"

        else:
            level = "Needs Preparation"

        actions = []

        if request.form.get("mfa") != "yes":
            actions.append(
                "Enable MFA on important accounts."
            )

        if request.form.get("phishing_resistant") != "yes":
            actions.append(
                "Evaluate passkeys or security keys."
            )

        if request.form.get("recovery") != "yes":
            actions.append(
                "Review and protect account recovery methods."
            )

        if request.form.get("device") != "yes":
            actions.append(
                "Check whether your primary devices support secure authentication."
            )

        if request.form.get("password_manager") != "yes":
            actions.append(
                "Use a password manager for remaining password-based accounts."
            )

        if not actions:

            actions.append(
                "Maintain your current controls and review passwordless support periodically."
            )

        result = {
            "score": score,
            "level": level,
            "actions": actions,
        }

        # Record the readiness assessment in the live audit log.
        try:

            conn = get_database_connection()

            try:

                log_event(
                    conn,
                    target_type="PASSWORDLESS_READINESS",
                    target_id=session["user_id"],
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get(
                        "User-Agent"
                    ),
                    metadata={
                        "action": "PASSWORDLESS_READINESS",
                        "score": score,
                        "level": level,
                    },
                )

            finally:

                conn.close()

        except Exception:
            pass

    return render_template(
        "passwordless_readiness.html",
        questions=questions,
        result=result,
    )


# =========================================================
# Admin Dashboard
# =========================================================

@app.route("/admin")
@admin_required
def admin():

    total_users = fetch_one(
        "SELECT COUNT(*) AS count FROM users"
    )["count"]

    total_assessments = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM assessment_results
        """
    )["count"]

    total_exposure_checks = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM exposure_checks
        """
    )["count"]

    recent_results = fetch_all(
        """
        SELECT
            u.name,
            u.email,
            a.score,
            a.readiness_level,
            a.created_at
        FROM assessment_results a
        LEFT JOIN users u
            ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 20
        """
    )

    audit_entries = fetch_all(
        """
        SELECT
            action,
            target_type,
            ip_address,
            created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT 50
        """
    )

    return render_template(
        "admin.html",
        total_users=total_users,
        total_assessments=total_assessments,
        total_exposure_checks=total_exposure_checks,
        recent_results=recent_results,
        audit_entries=audit_entries,
    )


# =========================================================
# Health API
# =========================================================

@app.route("/api/v1/health")
def health():

    try:

        conn = get_database_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT 1"
        )

        cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            "status": "healthy",
            "database": "connected",
        })

    except Exception as error:

        return jsonify({
            "status": "unhealthy",
            "database": "unavailable",
            "error": str(error),
        }), 503


# =========================================================
# API - Password Policy
# =========================================================

@app.route(
    "/api/v1/password-policy",
    methods=["POST"],
)
@login_required
def api_password_policy():

    data = request.get_json(
        silent=True
    ) or {}

    password = data.get(
        "password",
        "",
    )

    return jsonify(
        check_password_policy(
            password
        )
    )


# =========================================================
# API - Credential Exposure
# =========================================================

@app.route(
    "/api/v1/credential-exposure",
    methods=["POST"],
)
@login_required
def api_credential_exposure():

    data = request.get_json(
        silent=True
    ) or {}

    password = data.get(
        "password",
        "",
    )

    if not password:

        return jsonify({
            "error": "Password is required.",
        }), 400

    result = check_pwned_password(
        password
    )

    return jsonify(result)


# =========================================================
# Error Handlers
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "404.html"
    ), 404


@app.errorhandler(403)
def forbidden(error):

    return (
        "<h1>403 Forbidden</h1>"
        "<p>You do not have permission to access this page.</p>",
        403,
    )


# =========================================================
# Run Application
# =========================================================

if __name__ == "__main__":

    initialize_app()

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000",
            )
        ),
        debug=True,
    )