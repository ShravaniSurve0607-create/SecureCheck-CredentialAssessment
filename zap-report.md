# OWASP ZAP Security Testing

Run the application with `docker compose up --build`, then run:

```bash
docker run --network host -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://127.0.0.1:5000 -r zap-report.html
```

Review the generated report for:
- missing security headers
- cookie/session issues
- input validation findings
- reflected or stored XSS
- information disclosure
- error handling

Record each finding with: URL, risk, evidence, remediation, status, and retest date.

The CI workflow also runs a baseline ZAP scan and stores the report as a GitHub Actions artifact.
