# lh-web-auditor

[![CI](https://github.com/logihertz/lh-web-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-web-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

An asynchronous defensive web configuration auditor developed by **Logihertz Systems OPC Pvt Ltd** that inspects HTTP response headers, cookie security attributes, CORS policies, and TLS settings for authorized domains.

---

## Features

- **Asynchronous HTTP Engine**: Powered by `httpx` for high-throughput concurrent URL analysis.
- **Security Header Auditing**: Evaluates security headers against modern defense-in-depth best practices:
  - `Content-Security-Policy` (presence, unsafe directives, script-src wildcards, object-src, base-uri)
  - `Strict-Transport-Security` (HSTS presence, minimum max-age, includeSubDomains, preload)
  - `X-Frame-Options` (DENY, SAMEORIGIN, clickjacking protection)
  - `X-Content-Type-Options` (MIME sniffing prevention via `nosniff`)
  - `Referrer-Policy` (leakage prevention, secure fallbacks)
  - `Permissions-Policy` (hardware API restriction: camera, geolocation, microphone, etc.)
  - Information disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- **Cookie Security Attribute Inspection**: Checks all `Set-Cookie` directives for:
  - `Secure` flag (prevent transmission over unencrypted connections)
  - `HttpOnly` flag (mitigate client-side script theft / XSS impact)
  - `SameSite` attribute (`Strict`, `Lax`, or `None` with `Secure`)
  - Modern cookie prefix conformity (`__Host-` and `__Secure-`)
- **CORS Misconfiguration Probing**: Safely issues preflight requests to detect:
  - Insecure wildcard origin with credentials allowed (`*` with `Access-Control-Allow-Credentials: true`)
  - Arbitrary origin reflection with credentials allowed
  - Unrestricted origin reflection
  - Insecure `null` origin trust
- **TLS & Transport Security Verification**:
  - Validates HTTPS scheme enforcement and HTTP-to-HTTPS redirection
  - Inspects HTTP protocol versions (HTTP/1.1, HTTP/2)
- **Numerical Security Scoring (0–100)**:
  - Weighted penalty model (Critical: -25, High: -15, Medium: -8, Low: -4)
  - Letter grading from `A+` down to `F`
- **Flexible Export Formats**:
  - `table`: Terminal tables with rich color coding and summary panels
  - `json`: Machine-readable structured JSON report
  - `sarif`: OASIS SARIF v2.1.0 report for direct integration into GitHub Advanced Security Code Scanning

---

## Installation

Using `uv` (recommended):

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Using standard `pip`:

```bash
pip install .
```

---

## Usage

The CLI entrypoint is `lh-auditor`.

### Single URL Scan

Scan a single target URL and render results in the terminal:

```bash
lh-auditor scan https://example.com
```

Specify custom timeout, format, and output file:

```bash
lh-auditor scan https://example.com --timeout 10 --format json --output report.json
lh-auditor scan https://example.com --timeout 15 --format sarif --output results.sarif
```

### Batch URL Scan

Concurrently audit multiple domains from a text file:

```bash
lh-auditor batch urls.txt --concurrency 5 --format json --output batch-report.json
```

Where `urls.txt` contains one URL per line:
```text
https://example.com
https://api.example.com
http://legacy.example.com
```

---

## CLI Reference

### `lh-auditor scan`
```
Usage: lh-auditor scan [OPTIONS] URL

Arguments:
  URL  Target URL to scan (e.g. https://example.com)  [required]

Options:
  -t, --timeout FLOAT         Connection and read timeout in seconds  [default: 10.0]
  -f, --format [table|json|sarif] Output format  [default: table]
  -o, --output PATH           File path to write output  [default: None]
  --user-agent TEXT           Custom User-Agent header  [default: lh-web-auditor/0.1.0]
  --follow-redirects / --no-follow-redirects
                              Follow HTTP redirects  [default: True]
  --verify-ssl / --no-verify-ssl
                              Verify SSL/TLS certificates  [default: True]
  --help                      Show this message and exit.
```

### `lh-auditor batch`
```
Usage: lh-auditor batch [OPTIONS] FILE

Arguments:
  FILE  Path to text file containing URLs to audit (one per line)  [required]

Options:
  -c, --concurrency INTEGER   Maximum concurrent scan workers  [default: 5]
  -t, --timeout FLOAT         Connection and read timeout in seconds  [default: 10.0]
  -f, --format [table|json|sarif] Output format  [default: json]
  -o, --output PATH           File path to write output  [default: None]
  --user-agent TEXT           Custom User-Agent header  [default: lh-web-auditor/0.1.0]
  --follow-redirects / --no-follow-redirects
                              Follow HTTP redirects  [default: True]
  --verify-ssl / --no-verify-ssl
                              Verify SSL/TLS certificates  [default: True]
  --help                      Show this message and exit.
```

---

## Scoring Methodology

The auditor assesses defensive postures starting from **100 points**:

| Severity | Deduction | Description |
| -------- | --------- | ----------- |
| **CRITICAL** | -25 points | Severe exposure (e.g., CORS wildcard / origin reflection with credentials allowed). |
| **HIGH** | -15 points | Missing fundamental protections (missing CSP, missing HSTS, missing Secure on cookies over HTTPS). |
| **MEDIUM** | -8 points | Configuration weakness (missing HttpOnly, missing SameSite, permissive Referrer-Policy, weak CSP). |
| **LOW** | -4 points | Informational hardening (missing Permissions-Policy, missing subDomains/preload on HSTS). |
| **INFO** | 0 points | Informative findings (server banner disclosures). |

Scores are mapped to security grades:
- **A+**: 95 – 100
- **A**: 85 – 94
- **B**: 70 – 84
- **C**: 50 – 69
- **D**: 30 – 49
- **F**: 0 – 29

---

## Development & Testing

Run linting and static analysis:
```bash
ruff check .
bandit -r src/
```

Run test suite:
```bash
pytest -v
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
Copyright (c) 2026 Logihertz Systems OPC Pvt Ltd.

