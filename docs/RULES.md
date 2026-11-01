# Security Rules Reference: lh-web-auditor

An enterprise asynchronous web configuration & security header auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-web-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `SEC-HDR-CSP-MISSING` | `HIGH` | Security Headers | Content-Security-Policy (CSP) Header Missing or Unenforced |
| `SEC-HDR-HSTS-MISSING` | `CRITICAL` | Transport Security | Strict-Transport-Security (HSTS) Header Missing on HTTPS Origin |
| `SEC-HDR-XFO-MISSING` | `HIGH` | Clickjacking | X-Frame-Options Header Missing |
| `SEC-HDR-XCTO-MISSING` | `MEDIUM` | MIME Sniffing | X-Content-Type-Options Header Missing |
| `SEC-HDR-RP-UNSAFE` | `MEDIUM` | Information Disclosure | Referrer-Policy Header Missing or Permissive |
| `SEC-CK-NO-SECURE` | `HIGH` | Cookie Security | Authentication Cookie Missing Secure Flag Over HTTPS |
| `SEC-CK-NO-HTTPONLY` | `HIGH` | Cookie Security | Session Cookie Missing HttpOnly Flag |
| `SEC-CK-NO-SAMESITE` | `MEDIUM` | Cookie Security | Session Cookie Missing SameSite Attribute |
| `SEC-CORS-WILDCARD` | `HIGH` | CORS Policy | Overly Permissive CORS Access-Control-Allow-Origin: * |
| `SEC-DISC-SERVER-VERSION` | `LOW` | Information Disclosure | Detailed Server Software Banner or Version Disclosure |

---

## Granular Rule Specifications

### `SEC-HDR-CSP-MISSING`: Content-Security-Policy (CSP) Header Missing or Unenforced

- **Severity**: `HIGH`
- **Category**: `Security Headers`
- **Description**: Response lacks Content-Security-Policy header, leaving application vulnerable to XSS and data injection.
- **Remediation**: Deploy strict Content-Security-Policy with default-src 'self' and script nonce validation.

---

### `SEC-HDR-HSTS-MISSING`: Strict-Transport-Security (HSTS) Header Missing on HTTPS Origin

- **Severity**: `CRITICAL`
- **Category**: `Transport Security`
- **Description**: HTTPS endpoint does not emit Strict-Transport-Security header, risking downgrade attacks.
- **Remediation**: Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header.

---

### `SEC-HDR-XFO-MISSING`: X-Frame-Options Header Missing

- **Severity**: `HIGH`
- **Category**: `Clickjacking`
- **Description**: Response lacks X-Frame-Options header, allowing site framing and clickjacking.
- **Remediation**: Set X-Frame-Options: DENY or SAMEORIGIN on all HTML responses.

---

### `SEC-HDR-XCTO-MISSING`: X-Content-Type-Options Header Missing

- **Severity**: `MEDIUM`
- **Category**: `MIME Sniffing`
- **Description**: Response lacks X-Content-Type-Options: nosniff header, allowing browser MIME-sniffing exploits.
- **Remediation**: Add X-Content-Type-Options: nosniff to all HTTP response headers.

---

### `SEC-HDR-RP-UNSAFE`: Referrer-Policy Header Missing or Permissive

- **Severity**: `MEDIUM`
- **Category**: `Information Disclosure`
- **Description**: Referrer-Policy is missing or permits full URL leakage across cross-origin requests.
- **Remediation**: Configure Referrer-Policy: strict-origin-when-cross-origin on all endpoints.

---

### `SEC-CK-NO-SECURE`: Authentication Cookie Missing Secure Flag Over HTTPS

- **Severity**: `HIGH`
- **Category**: `Cookie Security`
- **Description**: Set-Cookie header sets session cookie without Secure flag on HTTPS connection.
- **Remediation**: Enforce Secure attribute on all cookies transmitted over HTTPS connections.

---

### `SEC-CK-NO-HTTPONLY`: Session Cookie Missing HttpOnly Flag

- **Severity**: `HIGH`
- **Category**: `Cookie Security`
- **Description**: Authentication cookie lacks HttpOnly flag, allowing JavaScript access and XSS theft.
- **Remediation**: Set HttpOnly flag on all session and authentication token cookies.

---

### `SEC-CK-NO-SAMESITE`: Session Cookie Missing SameSite Attribute

- **Severity**: `MEDIUM`
- **Category**: `Cookie Security`
- **Description**: Session cookie omits SameSite attribute, exposing requests to cross-site request forgery.
- **Remediation**: Configure SameSite=Lax or SameSite=Strict on all authentication cookies.

---

### `SEC-CORS-WILDCARD`: Overly Permissive CORS Access-Control-Allow-Origin: *

- **Severity**: `HIGH`
- **Category**: `CORS Policy`
- **Description**: Access-Control-Allow-Origin header set to * on authenticated or sensitive API routes.
- **Remediation**: Restrict Access-Control-Allow-Origin strictly to verified trusted frontend origins.

---

### `SEC-DISC-SERVER-VERSION`: Detailed Server Software Banner or Version Disclosure

- **Severity**: `LOW`
- **Category**: `Information Disclosure`
- **Description**: Server or X-Powered-By response headers disclose specific web server version details.
- **Remediation**: Suppress verbose server banners (ServerTokens Prod in Apache, server_tokens off in Nginx).

---
