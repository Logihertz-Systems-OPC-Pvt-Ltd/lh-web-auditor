"""Tests for the asynchronous WebAuditor engine using respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from lh_web_auditor.scanner import WebAuditor


def test_url_normalization() -> None:
    """URLs without scheme should automatically receive https://."""
    assert WebAuditor.normalize_url("example.com") == "https://example.com"
    assert WebAuditor.normalize_url("http://example.com") == "http://example.com"
    assert WebAuditor.normalize_url("https://example.com/api") == "https://example.com/api"


@pytest.mark.asyncio
async def test_scan_secure_site(secure_headers: dict[str, str]) -> None:
    """Auditing a fully hardened website produces Grade A+ and 100 score."""
    target_url = "https://secure-app.example.com"

    with respx.mock(base_url=target_url) as respx_mock:
        # Mock main response
        respx_mock.get("/").respond(
            status_code=200,
            headers=secure_headers,
            text="<html>Secure Portal</html>",
        )
        # Mock preflight OPTIONS response
        respx_mock.options("/").respond(
            status_code=204,
            headers={"access-control-allow-origin": "https://trusted-app.example.com"},
        )

        auditor = WebAuditor(timeout=5.0)
        result = await auditor.scan(target_url)

        assert result.is_successful is True
        assert result.status_code == 200
        assert result.score == 100
        assert result.grade == "A+"
        assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_scan_insecure_site() -> None:
    """Auditing an insecure website detects multiple findings and lowers score."""
    target_url = "https://insecure-app.example.com"

    insecure_headers = {
        "content-type": "text/html",
        "set-cookie": "session_id=12345",  # missing Secure, HttpOnly, SameSite
        "server": "nginx/1.18.0",
    }

    with respx.mock(base_url=target_url) as respx_mock:
        respx_mock.get("/").respond(
            status_code=200,
            headers=insecure_headers,
            text="<html>Insecure Portal</html>",
        )
        # Preflight returns reflection with credentials
        respx_mock.options("/").respond(
            status_code=200,
            headers={
                "access-control-allow-origin": "https://evil-attacker.example.com",
                "access-control-allow-credentials": "true",
            },
        )

        auditor = WebAuditor(timeout=5.0)
        result = await auditor.scan(target_url)

        assert result.is_successful is True
        assert result.score < 50
        assert result.grade in ("D", "F")
        assert len(result.cookies) == 1

        finding_ids = {f.id for f in result.findings}
        assert "SEC-HDR-CSP-MISSING" in finding_ids
        assert "SEC-HDR-HSTS-MISSING" in finding_ids
        assert "SEC-CK-NO-SECURE" in finding_ids
        assert "SEC-CK-NO-HTTPONLY" in finding_ids
        assert "SEC-CORS-REFLECTED-CREDENTIALS" in finding_ids


@pytest.mark.asyncio
async def test_scan_connection_error() -> None:
    """Network connection errors are handled cleanly and yield score 0 / Grade F."""
    target_url = "https://unreachable-host.example.com"

    with respx.mock(base_url=target_url) as respx_mock:
        respx_mock.get("/").mock(side_effect=httpx.ConnectError("Failed to resolve host"))

        auditor = WebAuditor(timeout=1.0)
        result = await auditor.scan(target_url)

        assert result.is_successful is False
        assert result.score == 0
        assert result.grade == "F"
        assert result.error is not None
        assert "ConnectError" in result.error
        assert len(result.findings) == 1
        assert result.findings[0].id == "SEC-CONN-ERROR"


@pytest.mark.asyncio
async def test_scan_batch(secure_headers: dict[str, str]) -> None:
    """Batch scan executes concurrently across multiple URLs."""
    urls = [
        "https://site-a.example.com",
        "https://site-b.example.com",
    ]

    with respx.mock as respx_mock:
        for u in urls:
            respx_mock.get(u).respond(status_code=200, headers=secure_headers)
            respx_mock.options(u).respond(status_code=204)

        auditor = WebAuditor(timeout=5.0)
        batch = await auditor.scan_batch(urls, concurrency=2)

        assert batch.total_scanned == 2
        assert len(batch.results) == 2
        assert batch.average_score == 100.0
