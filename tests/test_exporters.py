"""Tests for result exporters (table, JSON, SARIF)."""

from __future__ import annotations

import json

from lh_web_auditor.exporters.json_export import export_batch_json, export_scan_json
from lh_web_auditor.exporters.sarif import export_batch_sarif, export_scan_sarif
from lh_web_auditor.exporters.table import render_batch_table, render_scan_table
from lh_web_auditor.models import (
    BatchResult,
    Category,
    CookieFinding,
    CorsProbeResult,
    Finding,
    ScanResult,
    Severity,
    TlsAuditResult,
)


def _make_dummy_scan_result() -> ScanResult:
    finding = Finding(
        id="SEC-HDR-CSP-MISSING",
        title="Missing Content-Security-Policy",
        category=Category.HEADERS,
        severity=Severity.HIGH,
        description="CSP missing from response.",
        evidence="Header not found",
        recommendation="Configure CSP header",
        cwe_id="CWE-1021",
    )
    cookie = CookieFinding(
        name="sess",
        secure=False,
        httponly=True,
        samesite="Lax",
        path="/",
        domain=None,
        raw="sess=abc; HttpOnly; SameSite=Lax",
    )
    cors = CorsProbeResult(
        tested_origin="https://evil.com",
        allow_origin="*",
        allow_credentials=False,
        is_wildcard=True,
        is_reflected=False,
        is_vulnerable=False,
    )
    tls = TlsAuditResult(
        scheme="https",
        is_https=True,
        redirects_to_https=False,
        http_version="HTTP/1.1",
        status_code=200,
    )
    return ScanResult(
        target_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_time_ms=45.2,
        timestamp="2026-11-01T12:00:00Z",
        headers={"content-type": "text/html"},
        findings=[finding],
        score=85,
        grade="A",
        cookies=[cookie],
        cors=cors,
        tls=tls,
    )


def test_table_render_scan() -> None:
    """Table renderer returns non-empty formatted terminal report."""
    result = _make_dummy_scan_result()
    output = render_scan_table(result)
    assert "Logihertz Defensive Web Auditor" in output
    assert "https://example.com" in output
    assert "SEC-HDR-CSP-MISSING" in output
    assert "Set-Cookie Security Attributes" in output
    assert "CORS Probe Details" in output


def test_table_render_batch() -> None:
    """Batch table renderer formats aggregate summary."""
    result = _make_dummy_scan_result()
    batch = BatchResult(
        timestamp="2026-11-01T12:00:00Z",
        total_scanned=1,
        average_score=85.0,
        results=[result],
    )
    output = render_batch_table(batch)
    assert "Batch Security Audit Summary" in output
    assert "85.0/100" in output


def test_json_scan_export() -> None:
    """Exporting scan result to JSON creates valid structured JSON."""
    result = _make_dummy_scan_result()
    json_str = export_scan_json(result)
    data = json.loads(json_str)
    assert data["tool"]["name"] == "lh-web-auditor"
    assert data["scan"]["score"] == 85
    assert data["scan"]["grade"] == "A"
    assert len(data["scan"]["findings"]) == 1
    assert data["scan"]["findings"][0]["id"] == "SEC-HDR-CSP-MISSING"


def test_json_batch_export() -> None:
    """Exporting batch result to JSON produces valid JSON."""
    result = _make_dummy_scan_result()
    batch = BatchResult(
        timestamp="2026-11-01T12:00:00Z",
        total_scanned=1,
        average_score=85.0,
        results=[result],
    )
    json_str = export_batch_json(batch)
    data = json.loads(json_str)
    assert data["batch"]["total_scanned"] == 1
    assert len(data["batch"]["results"]) == 1


def test_sarif_scan_export() -> None:
    """SARIF output satisfies OASIS SARIF v2.1.0 JSON format."""
    result = _make_dummy_scan_result()
    sarif_str = export_scan_sarif(result)
    doc = json.loads(sarif_str)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-web-auditor"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "SEC-HDR-CSP-MISSING"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "SEC-HDR-CSP-MISSING"
    assert run["results"][0]["level"] == "error"


def test_sarif_batch_export() -> None:
    """Batch SARIF export includes all findings across multiple scans."""
    result = _make_dummy_scan_result()
    batch = BatchResult(
        timestamp="2026-11-01T12:00:00Z",
        total_scanned=1,
        average_score=85.0,
        results=[result],
    )
    sarif_str = export_batch_sarif(batch)
    doc = json.loads(sarif_str)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1

