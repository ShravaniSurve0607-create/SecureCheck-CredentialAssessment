# SecureCheck – Enhanced Security Project

This version adds the requested Person 2 security work.

## Added
1. Privacy-preserving breached-hash prefix lookup using SHA-1 k-anonymity.
2. Password policy checker: length, upper/lower/number/special characters, weak/common password checks, feedback.
3. Credential exposure rules and action guidance.
4. Security recommendations.
5. Audit logs for login, assessment, exposure checks, profile/admin actions.
6. Operational telemetry: response time, request path/status, 24-hour error summary.
7. Automated pytest security tests.
8. Docker + MySQL containerized setup.
9. GitHub Actions CI for tests and ZAP baseline scan.
10. OpenAPI 3 documentation in `openapi.yaml` and `/api/v1/openapi.json`.
11. OWASP ZAP testing instructions in `zap-report.md`.
12. Privacy/security review in `SECURITY_REVIEW.md`.
13. CSRF protection and secure session-cookie settings.
14. Environment-based database credentials; the previous hard-coded DB password was removed.

## Important privacy behavior
The password is never stored in plaintext. For breached-password checking:
- password stays in application memory;
- SecureCheck computes SHA-1 locally;
- only the first 5 hash characters are sent to the external range API;
- returned suffixes are compared locally;
- audit logs store the result/count and prefix only, never the password.

## Local Windows/VS Code setup

1. Install Python 3.12+ and MySQL 8.
2. Open this project folder in VS Code.
3. Create a virtual environment:
   `python -m venv venv`
4. Activate it:
   `venv\Scripts\activate`
5. Install:
   `pip install -r requirements.txt`
6. Set your environment variables from `.env.example`.
7. Start MySQL.
8. Run:
   `python app.py`
9. Open `http://127.0.0.1:5000`
10. Create an admin with:
    `python create_admin.py`

## Docker
Run:
`docker compose up --build`

Open:
`http://127.0.0.1:5000`

Stop:
`docker compose down`

## Tests
With MySQL available:
`pytest -q`

## API documentation
Open `openapi.yaml` or visit:
`http://127.0.0.1:5000/api/v1/openapi.json`

## ZAP
See `zap-report.md`.

Before real deployment, use HTTPS, a strong random `SECRET_KEY`, a real retention policy, restricted DB networking, and review all ZAP findings.
