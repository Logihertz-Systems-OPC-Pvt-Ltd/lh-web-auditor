"""Tests for TLS and transport security rules."""

from __future__ import annotations

from lh_web_auditor.models import Severity
from lh_web_auditor.rules.tls import evaluate_tls


def test_https_target() -> None:
    """An HTTPS target should yield no security warnings."""
    tls_result, findings = evaluate_tls(
        target_url="https://secure.example.com",
        final_url="https://secure.example.com/login",
        status_code=200,
        http_version="HTTP/2",
    )
    assert tls_result.is_https is True
    assert tls_result.redirects_to_https is False
    assert len(findings) == 0


def test_http_target_without_redirect() -> None:
    """An unencrypted HTTP target without HTTPS redirect triggers HIGH severity."""
    tls_result, findings = evaluate_tls(
        target_url="http://insecure.example.com",
        final_url="http://insecure.example.com/page",
        status_code=200,
    )
    assert tls_result.is_https is False
    assert len(findings) == 1
    assert findings[0].id == "SEC-TLS-CLEARTEXT-HTTP"
    assert findings[0].severity == Severity.HIGH


def test_http_target_redirects_to_https() -> None:
    """An HTTP target that redirects to HTTPS triggers an INFO finding."""
    tls_result, findings = evaluate_tls(
        target_url="http://example.com",
        final_url="https://example.com/",
        status_code=200,
    )
    assert tls_result.is_https is True
    assert tls_result.redirects_to_https is True
    assert len(findings) == 1
    assert findings[0].id == "SEC-TLS-HTTP-REDIRECT-SUCCESS"
    assert findings[0].severity == Severity.INFO

