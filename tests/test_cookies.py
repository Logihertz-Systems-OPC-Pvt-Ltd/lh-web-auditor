"""Tests for cookie security attribute evaluation rules."""

from __future__ import annotations

from lh_web_auditor.rules.cookies import evaluate_cookies, parse_cookie_header


def test_parse_cookie_header() -> None:
    """Validate parsing of Set-Cookie header strings."""
    raw = "session_id=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com"
    cookie = parse_cookie_header(raw)
    assert cookie.name == "session_id"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Strict"
    assert cookie.path == "/"
    assert cookie.domain == "example.com"


def test_missing_all_cookie_flags() -> None:
    """A naked cookie without flags triggers Secure, HttpOnly, and SameSite findings."""
    cookies, findings = evaluate_cookies(["auth_token=secret123"], is_https=True)
    assert len(cookies) == 1
    ids = {f.id for f in findings}
    assert "SEC-CK-NO-SECURE" in ids
    assert "SEC-CK-NO-HTTPONLY" in ids
    assert "SEC-CK-NO-SAMESITE" in ids


def test_samesite_none_without_secure() -> None:
    """SameSite=None without Secure triggers HIGH severity finding."""
    _, findings = evaluate_cookies(["tracker=xyz; SameSite=None"], is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-CK-SAMESITE-NONE-INSECURE" in ids


def test_samesite_none_with_secure() -> None:
    """SameSite=None with Secure triggers a LOW severity informational finding."""
    _, findings = evaluate_cookies(["tracker=xyz; SameSite=None; Secure; HttpOnly"], is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-CK-SAMESITE-NONE" in ids
    assert "SEC-CK-NO-SECURE" not in ids


def test_host_prefix_violations() -> None:
    """__Host- prefix requires Secure, Path=/, and no Domain."""
    # Violating: missing Secure and has Domain
    _, findings = evaluate_cookies(["__Host-id=1; Domain=example.com; Path=/"], is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-CK-HOST-PREFIX-VIOLATION" in ids

    # Valid __Host- cookie
    _, valid_findings = evaluate_cookies(
        ["__Host-id=1; Secure; HttpOnly; SameSite=Strict; Path=/"], is_https=True
    )
    valid_ids = {f.id for f in valid_findings}
    assert "SEC-CK-HOST-PREFIX-VIOLATION" not in valid_ids


def test_secure_prefix_violations() -> None:
    """__Secure- prefix requires Secure."""
    _, findings = evaluate_cookies(["__Secure-id=1; HttpOnly"], is_https=True)
    ids = {f.id for f in findings}
    assert "SEC-CK-SECURE-PREFIX-VIOLATION" in ids


def test_fully_secure_cookie() -> None:
    """Fortified cookie passes without findings."""
    cookies, findings = evaluate_cookies(
        ["session=123; Secure; HttpOnly; SameSite=Lax; Path=/"], is_https=True
    )
    assert len(cookies) == 1
    assert len(findings) == 0
