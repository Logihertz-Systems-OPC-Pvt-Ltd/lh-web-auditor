"""Tests for the CLI interface using Typer CliRunner and respx."""

from __future__ import annotations

import json
from pathlib import Path

import respx
from typer.testing import CliRunner

from lh_web_auditor.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    """Invoking with --version displays version and author."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lh-auditor v0.1.0" in result.stdout
    assert "Logihertz Systems OPC Pvt Ltd" in result.stdout


def test_cli_scan_table(secure_headers: dict[str, str]) -> None:
    """Scan command in table format prints rich table to console."""
    url = "https://example.com"
    with respx.mock:
        respx.get(url).respond(status_code=200, headers=secure_headers)
        respx.options(url).respond(status_code=204)

        result = runner.invoke(app, ["scan", url, "--format", "table"])
        assert result.exit_code == 0
        assert "Logihertz Defensive Web Auditor" in result.stdout
        assert "Security Score:" in result.stdout


def test_cli_scan_json(secure_headers: dict[str, str]) -> None:
    """Scan command in JSON format outputs valid JSON."""
    url = "https://example.com"
    with respx.mock:
        respx.get(url).respond(status_code=200, headers=secure_headers)
        respx.options(url).respond(status_code=204)

        result = runner.invoke(app, ["scan", url, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["tool"]["name"] == "lh-web-auditor"
        assert data["scan"]["score"] == 100


def test_cli_scan_sarif(secure_headers: dict[str, str]) -> None:
    """Scan command in SARIF format outputs valid SARIF document."""
    url = "https://example.com"
    with respx.mock:
        respx.get(url).respond(status_code=200, headers=secure_headers)
        respx.options(url).respond(status_code=204)

        result = runner.invoke(app, ["scan", url, "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"


def test_cli_scan_to_output_file(tmp_path: Path, secure_headers: dict[str, str]) -> None:
    """Scan command writes report to specified output path."""
    url = "https://example.com"
    out_file = tmp_path / "report.json"

    with respx.mock:
        respx.get(url).respond(status_code=200, headers=secure_headers)
        respx.options(url).respond(status_code=204)

        result = runner.invoke(app, ["scan", url, "--format", "json", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert content["scan"]["score"] == 100


def test_cli_batch(tmp_path: Path, secure_headers: dict[str, str]) -> None:
    """Batch command processes URLs from file and formats JSON output."""
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://alpha.example.com\nhttps://beta.example.com\n", encoding="utf-8")

    with respx.mock:
        respx.get("https://alpha.example.com").respond(status_code=200, headers=secure_headers)
        respx.options("https://alpha.example.com").respond(status_code=204)
        respx.get("https://beta.example.com").respond(status_code=200, headers=secure_headers)
        respx.options("https://beta.example.com").respond(status_code=204)

        result = runner.invoke(
            app, ["batch", str(urls_file), "--concurrency", "2", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["batch"]["total_scanned"] == 2
        assert data["batch"]["average_score"] == 100.0


def test_cli_batch_empty_file(tmp_path: Path) -> None:
    """Batch command warns and exits if input file contains no URLs."""
    urls_file = tmp_path / "empty.txt"
    urls_file.write_text("# Only comments\n\n", encoding="utf-8")

    result = runner.invoke(app, ["batch", str(urls_file)])
    assert result.exit_code == 1
    assert "No valid URLs found" in result.stdout
