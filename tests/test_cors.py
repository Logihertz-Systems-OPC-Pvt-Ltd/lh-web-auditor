"""Tests for CORS policy and preflight evaluation rules."""

from __future__ import annotations

from lh_web_auditor.models import Severity
from lh_web_auditor.rules.cors import evaluate_cors_response

_ATTACKER_ORIGIN = "https://evil-attacker.example.com"


def test_cors_origin_reflection_with_credentials() -> None:
    """Reflecting origin with credentials allowed is CRITICAL."""
    headers = {
        "access-control-allow-origin": _ATTACKER_ORIGIN,
        "access-control-allow-credentials": "true",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_reflected is True
    assert probe.allow_credentials is True
    assert probe.is_vulnerable is True
    assert len(findings) == 1
    assert findings[0].id == "SEC-CORS-REFLECTED-CREDENTIALS"
    assert findings[0].severity == Severity.CRITICAL


def test_cors_wildcard_with_credentials() -> None:
    """Wildcard with credentials allowed is CRITICAL."""
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_wildcard is True
    assert probe.is_vulnerable is True
    assert findings[0].id == "SEC-CORS-WILDCARD-CREDENTIALS"
    assert findings[0].severity == Severity.CRITICAL


def test_cors_origin_reflection_without_credentials() -> None:
    """Reflecting origin without credentials is HIGH severity."""
    headers = {
        "access-control-allow-origin": _ATTACKER_ORIGIN,
        "access-control-allow-credentials": "false",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_reflected is True
    assert probe.is_vulnerable is True
    assert findings[0].id == "SEC-CORS-REFLECTED-NO-CREDENTIALS"
    assert findings[0].severity == Severity.HIGH


def test_cors_null_origin() -> None:
    """Allowing null origin is HIGH severity."""
    headers = {
        "access-control-allow-origin": "null",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_vulnerable is True
    assert findings[0].id == "SEC-CORS-NULL-ORIGIN"
    assert findings[0].severity == Severity.HIGH


def test_cors_wildcard_without_credentials() -> None:
    """Wildcard origin without credentials triggers a LOW severity finding."""
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "false",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_wildcard is True
    assert len(findings) == 1
    assert findings[0].id == "SEC-CORS-WILDCARD"
    assert findings[0].severity == Severity.LOW


def test_cors_no_headers_or_unrelated_origin() -> None:
    """No CORS headers or static different origin yields no vulnerability."""
    headers = {
        "access-control-allow-origin": "https://trusted-partner.example.com",
    }
    probe, findings = evaluate_cors_response(headers, tested_origin=_ATTACKER_ORIGIN)
    assert probe.is_reflected is False
    assert probe.is_wildcard is False
    assert probe.is_vulnerable is False
    assert len(findings) == 0

