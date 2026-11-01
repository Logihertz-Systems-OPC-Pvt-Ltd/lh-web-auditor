# lh-web-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise asynchronous web configuration & security header auditor developed by **Logihertz Systems (OPC) Private Limited**.

Asynchronous defensive web configuration auditor developed by Logihertz Systems (OPC) Private Limited that inspects HTTP response headers, cookie security attributes, CORS preflight policies, and TLS configurations for authorized domains.

---

## Key Features

- **Asynchronous Concurrent Scanning**: Scans single endpoints or bulk URL inventories concurrently using asynchronous HTTP clients (`httpx`).
- **Security Headers Evaluation**: Audits Content-Security-Policy (CSP), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Cookie Security Attribute Auditing**: Inspects Set-Cookie headers for missing `Secure`, `HttpOnly`, and `SameSite` flags.
- **CORS Policy Preflight Verification**: Tests Cross-Origin Resource Sharing behavior using safe preflight probes to detect wildcard and credential reflections.
- **Objective Numerical Security Scoring**: Calculates a normalized 0-100 security score with weighted category penalties.
- **Multi-Format Reporting**: Outputs colored terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `SEC-HDR-CSP-MISSING` | `HIGH` | Content-Security-Policy header is missing or unenforced |
| `SEC-HDR-HSTS-MISSING` | `CRITICAL` | Strict-Transport-Security (HSTS) header is missing on HTTPS origin |
| `SEC-HDR-XFO-MISSING` | `HIGH` | X-Frame-Options header missing (susceptible to clickjacking) |
| `SEC-HDR-XCTO-MISSING` | `MEDIUM` | X-Content-Type-Options: nosniff header is missing |
| `SEC-HDR-RP-UNSAFE` | `MEDIUM` | Referrer-Policy is missing or allows cleartext origin leakage |
| `SEC-CK-NO-SECURE` | `HIGH` | Authentication cookie missing Secure flag over HTTPS transport |
| `SEC-CK-NO-HTTPONLY` | `HIGH` | Session cookie missing HttpOnly flag (vulnerable to XSS theft) |
| `SEC-CK-NO-SAMESITE` | `MEDIUM` | Session cookie missing SameSite attribute (CSRF risk) |
| `SEC-CORS-WILDCARD` | `HIGH` | Overly permissive Access-Control-Allow-Origin: * on authenticated route |
| `SEC-DISC-SERVER-VERSION` | `LOW` | Detailed server software banner or technology version disclosure |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor.git
cd lh-web-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-auditor` (also accessible via `lh-auditor`).

```bash
# Scan a live web endpoint for security headers and cookies
lh-auditor scan https://example.com

# Batch scan multiple target URLs concurrently
lh-auditor batch urls.txt --concurrency 5 --format json

# Export findings to OASIS SARIF v2.1.0
lh-auditor scan https://example.com --format sarif --output web-audit.sarif

# Custom request timeout and redirect policy
lh-auditor scan https://example.com --timeout 15
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited**.
