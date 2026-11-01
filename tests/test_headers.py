"""Tests for security header audit rules."""

from __future__ import annotations

from lh_web_auditor.models import Severity
from lh_web_auditor.rules.headers import (
    check_content_security_policy,
    check_information_disclosure,
    check_permissions_policy,
    check_referrer_policy,
    check_strict_transport_security,
    check_x_content_type_options,
    check_x_frame_options,
    evaluate_headers,
)


def test_missing_csp() -> None:
    """Missing CSP header triggers a HIGH severity finding."""
    findings = check_content_security_policy({})
    assert len(findings) == 1
    assert findings[0].id == "SEC-HDR-CSP-MISSING"
    assert findings[0].severity == Severity.HIGH


def test_csp_unsafe_directives() -> None:
    """Unsafe-inline and unsafe-eval in CSP trigger findings."""
    headers = {
        "content-security-policy": (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; "
            "object-src 'none'; base-uri 'self'"
        )
    }
    findings = check_content_security_policy(headers)
    ids = {f.id for f in findings}
    assert "SEC-HDR-CSP-UNSAFE-INLINE" in ids
    assert "SEC-HDR-CSP-UNSAFE-EVAL" in ids
    assert "SEC-HDR-CSP-WILDCARD-SCRIPT" in ids


def test_csp_missing_object_and_base() -> None:
    """Missing object-src and base-uri trigger LOW findings."""
    headers = {"content-security-policy": "default-src 'self'"}
    findings = check_content_security_policy(headers)
    ids = {f.id for f in findings}
    assert "SEC-HDR-CSP-OBJECT-SRC" in ids
    assert "SEC-HDR-CSP-BASE-URI" in ids


def test_hsts_missing_on_https() -> None:
    """Missing HSTS on HTTPS triggers HIGH severity."""
    findings = check_strict_transport_security({}, is_https=True)
    assert len(findings) == 1
    assert findings[0].id == "SEC-HDR-HSTS-MISSING"
    assert findings[0].severity == Severity.HIGH


def test_hsts_ignored_on_plain_http() -> None:
    """HSTS check produces no finding if connection is plain HTTP."""
    findings = check_strict_transport_security({}, is_https=False)
    assert len(findings) == 0


def test_hsts_max_age_zero() -> None:
    """HSTS max-age=0 triggers HIGH severity."""
    headers = {"strict-transport-security": "max-age=0"}
    findings = check_strict_transport_security(headers, is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-HDR-HSTS-DISABLED" in ids


def test_hsts_short_duration_and_no_subdomains() -> None:
    """Short max-age and missing includeSubdomains trigger findings."""
    headers = {"strict-transport-security": "max-age=86400"}
    findings = check_strict_transport_security(headers, is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-HDR-HSTS-SHORT-DURATION" in ids
    assert "SEC-HDR-HSTS-NO-SUBDOMAINS" in ids
    assert "SEC-HDR-HSTS-NO-PRELOAD" in ids


def test_x_frame_options_missing() -> None:
    """Missing X-Frame-Options triggers MEDIUM finding."""
    findings = check_x_frame_options({})
    assert len(findings) == 1
    assert findings[0].id == "SEC-HDR-XFO-MISSING"
    assert findings[0].severity == Severity.MEDIUM


def test_x_frame_options_valid() -> None:
    """DENY and SAMEORIGIN pass without findings."""
    assert not check_x_frame_options({"x-frame-options": "DENY"})
    assert not check_x_frame_options({"x-frame-options": "SAMEORIGIN"})


def test_x_frame_options_invalid() -> None:
    """Obsolete or unknown values trigger finding."""
    findings = check_x_frame_options({"x-frame-options": "ALLOW-FROM https://evil.com"})
    assert len(findings) == 1
    assert findings[0].id == "SEC-HDR-XFO-INVALID"


def test_x_content_type_options() -> None:
    """Missing or non-nosniff values trigger findings."""
    assert check_x_content_type_options({})[0].id == "SEC-HDR-XCTO-MISSING"
    assert (
        check_x_content_type_options({"x-content-type-options": "invalid"})[0].id
        == "SEC-HDR-XCTO-INVALID"
    )
    assert not check_x_content_type_options({"x-content-type-options": "nosniff"})


def test_referrer_policy() -> None:
    """Missing and unsafe referrer policies trigger findings."""
    assert check_referrer_policy({})[0].id == "SEC-HDR-RP-MISSING"
    assert check_referrer_policy({"referrer-policy": "unsafe-url"})[0].id == "SEC-HDR-RP-UNSAFE"
    assert not check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})


def test_permissions_policy() -> None:
    """Missing Permissions-Policy triggers LOW finding."""
    assert check_permissions_policy({})[0].id == "SEC-HDR-PP-MISSING"
    assert not check_permissions_policy({"permissions-policy": "geolocation=(), camera=()"})


def test_information_disclosure() -> None:
    """Server banner with version and X-Powered-By trigger findings."""
    headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
        "x-aspnet-version": "4.0.30319",
    }
    findings = check_information_disclosure(headers)
    ids = {f.id for f in findings}
    assert "SEC-DISC-SERVER-VERSION" in ids
    assert "SEC-DISC-X_POWERED_BY" in ids
    assert "SEC-DISC-X_ASPNET_VERSION" in ids


def test_evaluate_headers_all_passing(secure_headers: dict[str, str]) -> None:
    """Auditing fortified headers should return zero findings."""
    findings = evaluate_headers(secure_headers, is_https=True)
    assert not findings
