# Privacy & Security Review

## Password handling
- Registration passwords are stored only as Werkzeug password hashes.
- The password policy checker processes passwords in application memory and does not store or log them.
- The breached-password checker computes SHA-1 locally.
- Only the first 5 SHA-1 characters are sent to the Have I Been Pwned Pwned Passwords range API.
- The full password and full SHA-1 hash are not sent to the external service.
- Audit logs record only the result, not the password or hash.

## Data retention
- Assessment and exposure records remain in MySQL until an administrator applies the project's retention policy.
- Request telemetry and audit logs should be retained only as long as operationally necessary.
- Add a scheduled deletion job for the retention period selected by the deployment owner.

## Exposure-check privacy
- Email exposure demo checks are stored as email addresses because they are the feature's audit subject.
- Credential exposure records store only the 5-character hash prefix and result/count.
- A breach match is a risk signal, not proof that a current password is still in use.

## Authentication/session security
- Passwords use Werkzeug password hashing.
- Session cookies are HttpOnly and SameSite=Lax.
- CSRF tokens are required on POST forms.
- The secret key is loaded from an environment variable.
- Production deployments should use HTTPS and set SESSION_COOKIE_SECURE=1.
- Login success/failure and logout are audited.

## Operational telemetry
- Each request records method, path, status and response time.
- Admin telemetry summarizes request volume, average response time and errors for the previous 24 hours.
- Telemetry must not contain passwords or credential contents.

## Remaining deployment checks
- Put secrets in environment/secret storage, not source control.
- Restrict database network access.
- Enable HTTPS.
- Configure a concrete data-retention period.
- Review ZAP findings and remediate before production.
