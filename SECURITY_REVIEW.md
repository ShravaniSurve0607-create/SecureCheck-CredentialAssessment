# Privacy & Security Review

## Password handling

- Registration passwords are stored only as Werkzeug password hashes.
- Password policy checks are performed in application memory and passwords are not stored or written to application logs.
- The breached-password checker computes the SHA-1 hash locally.
- Only the first 5 SHA-1 hexadecimal characters are sent to the Pwned Passwords range API.
- The complete password and complete SHA-1 hash are not sent to the external breach-check service.
- Credential exposure records store only the hash prefix, exposure result, and match count.
- Audit logging does not intentionally record password values or complete credential hashes.

## Password policy

- Passwords are checked for minimum length.
- Uppercase, lowercase, numeric, and special-character requirements are enforced.
- A list of common passwords is checked locally.
- Policy violations are returned as actionable feedback.

## Exposure and risk handling

- Password exposure checks use a privacy-preserving hash-prefix lookup.
- A breach match is treated as a risk signal and does not prove that a password is currently in use.
- Exposure rules raise the risk level when a credential is breached, the password policy is not satisfied, or known exposure records exist.
- Recommended actions are presented to the user based on the detected risk.

## Authentication and session security

- Passwords use Werkzeug password hashing.
- Session cookies are configured with HttpOnly and SameSite=Lax protections.
- CSRF tokens are required for state-changing POST requests.
- The Flask secret key is loaded from an environment variable.
- Login success, login failure, and logout events are audited.
- Production deployments should use HTTPS and set `SESSION_COOKIE_SECURE=1`.

## Audit logging

- Security-related events can be recorded with event type, target information, client IP address, user-agent information, and optional metadata.
- Audit records must not contain passwords or complete credential hashes.
- Access to audit information should be restricted to authorized administrators.

## Operational telemetry

- Requests record method, path, HTTP status code, and response time.
- Operational metrics are stored for monitoring and troubleshooting.
- Telemetry must not contain passwords or credential contents.
- Production deployments should review telemetry retention and access controls.

## API security

- Password-policy and credential-exposure API operations require an authenticated session.
- Request data is validated before processing.
- The credential-exposure API uses the same privacy-preserving hash-prefix approach as the web interface.
- API documentation is provided in `openapi.yaml`.

## CI/CD and security testing

- Automated security tests are included in the `tests/` directory.
- GitHub Actions runs the automated test suite.
- GitHub Actions also runs an OWASP ZAP baseline scan against the application deployment.
- ZAP results should be reviewed and any applicable findings should be addressed before production deployment.

## Data retention

- Assessment and exposure records remain in MySQL according to the deployment's retention policy.
- Audit logs and request telemetry should be retained only for as long as operationally necessary.
- A concrete retention period should be selected by the deployment owner.
- Production deployments should implement scheduled deletion or archival when required by the selected retention policy.

## Deployment security checklist

- Store secrets in environment variables or a dedicated secret-management system.
- Never commit `.env` files or real passwords to source control.
- Restrict database network access.
- Use HTTPS in production.
- Set `SESSION_COOKIE_SECURE=1` when running behind HTTPS.
- Restrict administrative functionality to authorized users.
- Review OWASP ZAP findings before production deployment.
- Define and enforce an appropriate data-retention period.