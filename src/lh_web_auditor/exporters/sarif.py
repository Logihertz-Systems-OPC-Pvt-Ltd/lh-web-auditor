"""SARIF (Static Analysis Results Interchange Format) exporter for SARIF v2.1.0."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from lh_web_auditor.models import BatchResult, Finding, ScanResult, Severity

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map lh-web-auditor severity to SARIF result levels."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _build_rule_definition(finding: Finding) -> dict[str, Any]:
    """Construct a SARIF rule definition dictionary from a Finding."""
    help_uri = (
        f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html"
        if finding.cwe_id
        else "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor"
    )

    sec_sev = "8.0" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "5.0"

    return {
        "id": finding.id,
        "name": finding.id.replace("-", "_"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {
            "level": _severity_to_sarif_level(finding.severity),
        },
        "helpUri": help_uri,
        "properties": {
            "category": finding.category.value,
            "security-severity": sec_sev,
        },
    }


def _build_sarif_result(finding: Finding, target_url: str) -> dict[str, Any]:
    """Construct a SARIF result item from a Finding and its target URL."""
    return {
        "ruleId": finding.id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": f"{finding.title}: {finding.description} Evidence: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_url,
                    },
                }
            }
        ],
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category.value,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "cwe": finding.cwe_id,
        },
    }


def export_scan_sarif(result: ScanResult, indent: int = 2) -> str:
    """Export a single ScanResult in SARIF 2.1.0 format."""
    return export_results_sarif([result], indent=indent)


def export_batch_sarif(batch: BatchResult, indent: int = 2) -> str:
    """Export a BatchResult in SARIF 2.1.0 format."""
    return export_results_sarif(batch.results, indent=indent)


def export_results_sarif(results: Sequence[ScanResult], indent: int = 2) -> str:
    """Build and serialize a list of ScanResults to SARIF v2.1.0 format.

    Args:
        results: Collection of ScanResult instances.
        indent: Indentation for formatted output.

    Returns:
        SARIF formatted JSON string.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for res in results:
        for finding in res.findings:
            if finding.id not in rules_by_id:
                rules_by_id[finding.id] = _build_rule_definition(finding)
            sarif_results.append(_build_sarif_result(finding, target_url=res.target_url))

    sarif_doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-web-auditor",
                        "organization": "Logihertz Systems OPC Pvt Ltd",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
