# Specification: lh-web-auditor

## Overview
An asynchronous defensive web configuration auditor developed by Logihertz Systems OPC Pvt Ltd that inspects HTTP response headers, cookie security attributes, CORS policies, and TLS settings for authorized domains.

## Core Features
- Concurrently fetch target URLs using httpx (async) and evaluate Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy headers.
- Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags.
- Test Cross-Origin Resource Sharing (CORS) behavior using safe preflight requests to detect wildcard or origin-reflection misconfigurations.
- Calculate a numerical security score (0-100) and export findings in terminal tables or JSON/SARIF reports.

## CLI Interface (Entry point: lh-auditor)
- lh-auditor scan <url> --timeout 10 --format <table|json|sarif> --output <file>
- lh-auditor batch <urls.txt> --concurrency 5 --format json

## Deliverables
- Async scanner package under src/lh_web_auditor/ with httpx, typer, and rich dependencies.
- Unit tests under tests/ using mocked HTTP responses.
