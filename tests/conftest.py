"""Shared fixtures and mocks for unit tests."""

from __future__ import annotations

import pytest

from lh_web_auditor.models import Category, Finding, Severity


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample Finding instance for tests."""
    return Finding(
        id="SEC-TEST-001",
        title="Test Security Vulnerability",
        category=Category.HEADERS,
        severity=Severity.HIGH,
        description="A detailed test description.",
        evidence="Evidence value found in response.",
        recommendation="Apply the recommended patch.",
        cwe_id="CWE-79",
    )


@pytest.fixture
def secure_headers() -> dict[str, str]:
    """Headers for a properly fortified web service."""
    return {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": (
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
        ),
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=(), microphone=(), camera=()",
    }

