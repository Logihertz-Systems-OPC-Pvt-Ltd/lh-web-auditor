# ==============================================================================
# Product:       lh-web-auditor (lh-web)
# Module:        src.lh_web_auditor.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-web-auditor: Asynchronous defensive web configuration auditor.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Logihertz Systems OPC Pvt Ltd"

from lh_web_auditor.models import (
    BatchResult,
    Category,
    CookieFinding,
    CorsProbeResult,
    Finding,
    Format,
    ScanResult,
    Severity,
    TlsAuditResult,
)
from lh_web_auditor.scanner import WebAuditor

__all__ = [
    "BatchResult",
    "Category",
    "CookieFinding",
    "CorsProbeResult",
    "Finding",
    "Format",
    "ScanResult",
    "Severity",
    "TlsAuditResult",
    "WebAuditor",
    "__author__",
    "__version__",
]
