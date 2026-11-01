"""HTTP response security header evaluation rules."""

from __future__ import annotations

import re
from collections.abc import Mapping

from lh_web_auditor.models import Category, Finding, Severity

# Directives that allow code injection when present in script-src / default-src
_UNSAFE_INLINE = "'unsafe-inline'"
_UNSAFE_EVAL = "'unsafe-eval'"
_MIN_HSTS_MAX_AGE = 15552000  # 180 days in seconds


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Convert header names to lowercase for case-insensitive lookup."""
    return {k.lower(): v.strip() for k, v in headers.items()}


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """Parse a CSP header string into directive names and token lists."""
    directives: dict[str, list[str]] = {}
    for part in csp_value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def check_content_security_policy(headers: dict[str, str]) -> list[Finding]:
    """Audit the Content-Security-Policy header for presence and dangerous directives."""
    findings: list[Finding] = []
    csp = headers.get("content-security-policy")

    if not csp:
        findings.append(
            Finding(
                id="SEC-HDR-CSP-MISSING",
                title="Missing Content-Security-Policy Header",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                description=(
                    "Content-Security-Policy (CSP) is missing. CSP prevents Cross-Site Scripting "
                    "(XSS), clickjacking, and unauthorized resource injection."
                ),
                evidence="Header 'Content-Security-Policy' was not found in response.",
                recommendation=(
                    "Define a robust Content-Security-Policy header restricting script, style, "
                    "and object origins."
                ),
                cwe_id="CWE-1021",
            )
        )
        return findings

    directives = _parse_csp_directives(csp)

    # Check for script sources (falling back to default-src)
    script_sources = directives.get("script-src", directives.get("default-src", []))

    if not directives.get("default-src") and not directives.get("script-src"):
        findings.append(
            Finding(
                id="SEC-HDR-CSP-NO-FALLBACK",
                title="CSP Missing default-src and script-src Directives",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    "The CSP policy defines neither default-src nor script-src, allowing scripts "
                    "to be fetched from arbitrary origins."
                ),
                evidence=f"CSP: {csp}",
                recommendation="Add 'default-src 'self'' or 'script-src' with trusted domains.",
                cwe_id="CWE-79",
            )
        )

    if _UNSAFE_INLINE in script_sources:
        findings.append(
            Finding(
                id="SEC-HDR-CSP-UNSAFE-INLINE",
                title="CSP Permits 'unsafe-inline' Scripts",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    "The script-src or default-src directive contains 'unsafe-inline', disabling "
                    "CSP protection against inline Cross-Site Scripting (XSS)."
                ),
                evidence=f"script-src / default-src sources: {' '.join(script_sources)}",
                recommendation="Refactor inline scripts to external files with nonces or hashes.",
                cwe_id="CWE-79",
            )
        )

    if _UNSAFE_EVAL in script_sources:
        findings.append(
            Finding(
                id="SEC-HDR-CSP-UNSAFE-EVAL",
                title="CSP Permits 'unsafe-eval' Execution",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    "The script-src or default-src directive contains 'unsafe-eval', permitting "
                    "dynamic code evaluation (e.g. eval, setTimeout with string)."
                ),
                evidence=f"script-src / default-src sources: {' '.join(script_sources)}",
                recommendation=(
                    "Eliminate eval() and Function() calls to safely drop 'unsafe-eval'."
                ),
                cwe_id="CWE-95",
            )
        )

    if "*" in script_sources:
        findings.append(
            Finding(
                id="SEC-HDR-CSP-WILDCARD-SCRIPT",
                title="CSP Contains Wildcard (*) in Script Sources",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                description=(
                    "Wildcard '*' in script-src allows executable scripts from any origin."
                ),
                evidence=f"script-src sources: {' '.join(script_sources)}",
                recommendation="Restrict script-src to explicit trusted domains or nonces.",
                cwe_id="CWE-79",
            )
        )

    if "object-src" not in directives or directives.get("object-src") != ["'none'"]:
        obj_src = " ".join(directives.get("object-src", [])) or "missing"
        findings.append(
            Finding(
                id="SEC-HDR-CSP-OBJECT-SRC",
                title="CSP Missing 'object-src 'none'' Restriction",
                category=Category.HEADERS,
                severity=Severity.LOW,
                description=(
                    "Missing 'object-src 'none'' allows dangerous plugin execution (Flash, Java)."
                ),
                evidence=f"object-src directive: {obj_src}",
                recommendation="Add 'object-src 'none'' to the Content-Security-Policy.",
                cwe_id="CWE-79",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                id="SEC-HDR-CSP-BASE-URI",
                title="CSP Missing 'base-uri' Directive",
                category=Category.HEADERS,
                severity=Severity.LOW,
                description=(
                    "Without 'base-uri', attackers may inject <base> tags to hijack relative URLs."
                ),
                evidence="Directive 'base-uri' is missing from CSP.",
                recommendation="Set 'base-uri 'self'' or 'base-uri 'none''.",
                cwe_id="CWE-79",
            )
        )

    return findings


def check_strict_transport_security(headers: dict[str, str], is_https: bool) -> list[Finding]:
    """Audit the Strict-Transport-Security (HSTS) header."""
    findings: list[Finding] = []
    hsts = headers.get("strict-transport-security")

    if not is_https:
        return findings

    if not hsts:
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-MISSING",
                title="Missing Strict-Transport-Security Header",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                description=(
                    "HTTP Strict Transport Security (HSTS) instructs browsers to only connect over "
                    "HTTPS, mitigating man-in-the-middle SSL-stripping attacks."
                ),
                evidence="Header 'Strict-Transport-Security' was not found on HTTPS response.",
                recommendation=(
                    "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
                ),
                cwe_id="CWE-319",
            )
        )
        return findings

    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if not max_age_match:
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-INVALID",
                title="Invalid Strict-Transport-Security Header Format",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description="The HSTS header is missing a valid max-age directive.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Ensure max-age is set to an integer number of seconds.",
                cwe_id="CWE-319",
            )
        )
        return findings

    max_age = int(max_age_match.group(1))
    if max_age == 0:
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-DISABLED",
                title="Strict-Transport-Security Explicitly Disabled (max-age=0)",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                description=(
                    "An HSTS max-age of 0 instructs clients to discard cached HSTS policies."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Increase max-age to at least 15552000 (180 days).",
                cwe_id="CWE-319",
            )
        )
    elif max_age < _MIN_HSTS_MAX_AGE:
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-SHORT-DURATION",
                title="Strict-Transport-Security Duration Too Short",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    f"HSTS max-age is {max_age} seconds (less than the recommended 180 days / "
                    f"{_MIN_HSTS_MAX_AGE} seconds)."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Increase max-age to 31536000 (1 year) for production services.",
                cwe_id="CWE-319",
            )
        )

    if "includesubdomains" not in hsts.lower():
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-NO-SUBDOMAINS",
                title="Strict-Transport-Security Missing includeSubDomains",
                category=Category.HEADERS,
                severity=Severity.LOW,
                description="Subdomains remain susceptible to SSL-stripping attacks.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Add 'includeSubDomains' to ensure blanket coverage.",
                cwe_id="CWE-319",
            )
        )

    if "preload" not in hsts.lower():
        findings.append(
            Finding(
                id="SEC-HDR-HSTS-NO-PRELOAD",
                title="Strict-Transport-Security Missing preload Directive",
                category=Category.HEADERS,
                severity=Severity.INFO,
                description="The site is not configured for browser-level HSTS preloading.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Add 'preload' once configuration is tested across all subdomains.",
                cwe_id="CWE-319",
            )
        )

    return findings


def check_x_frame_options(headers: dict[str, str]) -> list[Finding]:
    """Audit the X-Frame-Options header for clickjacking protections."""
    findings: list[Finding] = []
    xfo = headers.get("x-frame-options")

    if not xfo:
        findings.append(
            Finding(
                id="SEC-HDR-XFO-MISSING",
                title="Missing X-Frame-Options Header",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    "X-Frame-Options is missing. Without framing restrictions, attackers can frame "
                    "the site in malicious iframes to perform clickjacking attacks."
                ),
                evidence="Header 'X-Frame-Options' was not returned.",
                recommendation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                cwe_id="CWE-1021",
            )
        )
        return findings

    val = xfo.upper()
    if val not in ("DENY", "SAMEORIGIN"):
        findings.append(
            Finding(
                id="SEC-HDR-XFO-INVALID",
                title="Non-Standard or Obsolete X-Frame-Options Value",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    f"X-Frame-Options has non-standard value '{xfo}'. Note that ALLOW-FROM is "
                    "deprecated and ignored by modern browsers."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                recommendation="Use 'DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors'.",
                cwe_id="CWE-1021",
            )
        )

    return findings


def check_x_content_type_options(headers: dict[str, str]) -> list[Finding]:
    """Audit the X-Content-Type-Options header."""
    findings: list[Finding] = []
    xcto = headers.get("x-content-type-options")

    if not xcto:
        findings.append(
            Finding(
                id="SEC-HDR-XCTO-MISSING",
                title="Missing X-Content-Type-Options Header",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    "Missing X-Content-Type-Options allows browsers to MIME-sniff responses away "
                    "from declared content-type, potentially executing text/plain as HTML/JS."
                ),
                evidence="Header 'X-Content-Type-Options' was not returned.",
                recommendation="Set 'X-Content-Type-Options: nosniff'.",
                cwe_id="CWE-79",
            )
        )
    elif xcto.lower() != "nosniff":
        findings.append(
            Finding(
                id="SEC-HDR-XCTO-INVALID",
                title="Invalid X-Content-Type-Options Value",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=f"X-Content-Type-Options value is '{xcto}' instead of 'nosniff'.",
                evidence=f"X-Content-Type-Options: {xcto}",
                recommendation="Set 'X-Content-Type-Options: nosniff'.",
                cwe_id="CWE-79",
            )
        )

    return findings


def check_referrer_policy(headers: dict[str, str]) -> list[Finding]:
    """Audit the Referrer-Policy header."""
    findings: list[Finding] = []
    rp = headers.get("referrer-policy")

    if not rp:
        findings.append(
            Finding(
                id="SEC-HDR-RP-MISSING",
                title="Missing Referrer-Policy Header",
                category=Category.HEADERS,
                severity=Severity.LOW,
                description=(
                    "Referrer-Policy header is missing. The browser will fall back to default "
                    "behavior, potentially leaking URL parameters across domains."
                ),
                evidence="Header 'Referrer-Policy' was not found.",
                recommendation=(
                    "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
                ),
                cwe_id="CWE-200",
            )
        )
        return findings

    unsafe_policies = {"unsafe-url", "no-referrer-when-downgrade"}
    val = rp.strip().lower()
    if val in unsafe_policies:
        findings.append(
            Finding(
                id="SEC-HDR-RP-UNSAFE",
                title="Permissive or Insecure Referrer-Policy",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                description=(
                    f"Referrer-Policy is configured as '{rp}', which leaks entire query parameters "
                    "and URLs across third-party domains."
                ),
                evidence=f"Referrer-Policy: {rp}",
                recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
                cwe_id="CWE-200",
            )
        )

    return findings


def check_permissions_policy(headers: dict[str, str]) -> list[Finding]:
    """Audit the Permissions-Policy header for hardware API containment."""
    findings: list[Finding] = []
    pp = headers.get("permissions-policy")

    if not pp:
        findings.append(
            Finding(
                id="SEC-HDR-PP-MISSING",
                title="Missing Permissions-Policy Header",
                category=Category.HEADERS,
                severity=Severity.LOW,
                description=(
                    "Permissions-Policy allows fine-grained control over browser features such as "
                    "camera, microphone, geolocation, and payment APIs."
                ),
                evidence="Header 'Permissions-Policy' was not returned.",
                recommendation=(
                    "Set Permissions-Policy to disable unnecessary browser features, e.g. "
                    "'geolocation=(), microphone=(), camera=()'."
                ),
                cwe_id="CWE-693",
            )
        )

    return findings


def check_information_disclosure(headers: dict[str, str]) -> list[Finding]:
    """Audit server and framework version disclosure headers."""
    findings: list[Finding] = []

    server = headers.get("server")
    if server and any(c.isdigit() for c in server):
        findings.append(
            Finding(
                id="SEC-DISC-SERVER-VERSION",
                title="Server Header Discloses Version Information",
                category=Category.DISCLOSURE,
                severity=Severity.INFO,
                description=(
                    "The Server response header discloses software name and version, assisting "
                    "attackers in locating version-specific CVE exploits."
                ),
                evidence=f"Server: {server}",
                recommendation="Strip or generalize the Server header in web server configuration.",
                cwe_id="CWE-200",
            )
        )

    for header_name in ("x-powered-by", "x-aspnet-version", "x-generator"):
        val = headers.get(header_name)
        if val:
            findings.append(
                Finding(
                    id=f"SEC-DISC-{header_name.upper().replace('-', '_')}",
                    title=f"Framework Information Disclosed ({header_name})",
                    category=Category.DISCLOSURE,
                    severity=Severity.LOW,
                    description=f"The '{header_name}' header discloses backend framework details.",
                    evidence=f"{header_name}: {val}",
                    recommendation=f"Remove the '{header_name}' response header in production.",
                    cwe_id="CWE-200",
                )
            )

    return findings


def evaluate_headers(headers: Mapping[str, str], is_https: bool) -> list[Finding]:
    """Execute all security header audit rules against the captured response headers.

    Args:
        headers: Mapping of raw HTTP response headers.
        is_https: True if the analyzed connection used TLS (HTTPS).

    Returns:
        List of detected security findings.
    """
    normalized = _normalize_headers(headers)
    findings: list[Finding] = []

    findings.extend(check_content_security_policy(normalized))
    findings.extend(check_strict_transport_security(normalized, is_https=is_https))
    findings.extend(check_x_frame_options(normalized))
    findings.extend(check_x_content_type_options(normalized))
    findings.extend(check_referrer_policy(normalized))
    findings.extend(check_permissions_policy(normalized))
    findings.extend(check_information_disclosure(normalized))

    return findings
