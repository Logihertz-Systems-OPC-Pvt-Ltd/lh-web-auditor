# ==============================================================================
# Product:       lh-web-auditor (lh-web)
# Module:        src.lh_web_auditor.exporters.json_export
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""JSON report serialization for scan and batch results."""

from __future__ import annotations

import json
from typing import Any

from lh_web_auditor.models import BatchResult, ScanResult

_SCHEMA_VERSION = "1.0.0"


def export_scan_json(result: ScanResult, indent: int = 2) -> str:
    """Serialize a single ScanResult into a formatted JSON string.

    Args:
        result: The ScanResult to export.
        indent: Indentation level for pretty-printing.

    Returns:
        JSON string representation.
    """
    payload: dict[str, Any] = {
        "$schema_version": _SCHEMA_VERSION,
        "tool": {
            "name": "lh-web-auditor",
            "vendor": "Logihertz Systems OPC Pvt Ltd",
            "version": "0.1.0",
        },
        "scan": result.to_dict(),
    }
    return json.dumps(payload, indent=indent)


def export_batch_json(batch: BatchResult, indent: int = 2) -> str:
    """Serialize a BatchResult into a formatted JSON string.

    Args:
        batch: The BatchResult to export.
        indent: Indentation level for pretty-printing.

    Returns:
        JSON string representation.
    """
    payload: dict[str, Any] = {
        "$schema_version": _SCHEMA_VERSION,
        "tool": {
            "name": "lh-web-auditor",
            "vendor": "Logihertz Systems OPC Pvt Ltd",
            "version": "0.1.0",
        },
        "batch": batch.to_dict(),
    }
    return json.dumps(payload, indent=indent)
