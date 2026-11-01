"""Domain models and data definitions for lh-web-auditor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Vulnerability and finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Format(StrEnum):
    """Supported output serialization formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class Category(StrEnum):
    """Audit category grouping for security findings."""

    HEADERS = "Security Headers"
    COOKIES = "Cookie Security"
    CORS = "CORS Policy"
    TLS = "TLS & Transport"
    DISCLOSURE = "Information Disclosure"


@dataclass(slots=True)
class Finding:
    """Represents an individual security finding or policy check result."""

    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    evidence: str
    recommendation: str
    cwe_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding instance to a dictionary with primitive types."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }


@dataclass(slots=True)
class CookieFinding:
    """Security attributes observed on a Set-Cookie response header."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    path: str | None
    domain: str | None
    raw: str

    def to_dict(self) -> dict[str, Any]:
        """Convert cookie finding instance to a dictionary."""
        return asdict(self)


@dataclass(slots=True)
class CorsProbeResult:
    """Outcome of active CORS preflight / reflection probing."""

    tested_origin: str
    allow_origin: str | None
    allow_credentials: bool
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    status_code: int = 0
    is_wildcard: bool = False
    is_reflected: bool = False
    is_vulnerable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert CORS probe result to a dictionary."""
        return asdict(self)


@dataclass(slots=True)
class TlsAuditResult:
    """Transport layer security and scheme audit metrics."""

    scheme: str
    is_https: bool
    redirects_to_https: bool
    http_version: str | None
    status_code: int

    def to_dict(self) -> dict[str, Any]:
        """Convert TLS audit result to a dictionary."""
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    """Comprehensive scan outcome for a single target URL."""

    target_url: str
    final_url: str
    status_code: int
    response_time_ms: float
    timestamp: str
    headers: dict[str, str]
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"
    cookies: list[CookieFinding] = field(default_factory=list)
    cors: CorsProbeResult | None = None
    tls: TlsAuditResult | None = None
    error: str | None = None

    @property
    def is_successful(self) -> bool:
        """Return True if the audit completed without fatal connection errors."""
        return self.error is None

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return counts of findings grouped by severity."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to a dictionary representation."""
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "timestamp": self.timestamp,
            "headers": self.headers,
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "cookies": [c.to_dict() for c in self.cookies],
            "cors": self.cors.to_dict() if self.cors else None,
            "tls": self.tls.to_dict() if self.tls else None,
            "error": self.error,
        }


@dataclass(slots=True)
class BatchResult:
    """Aggregated scan outcomes across multiple target URLs."""

    timestamp: str
    total_scanned: int
    average_score: float
    results: list[ScanResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert batch result to a dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "total_scanned": self.total_scanned,
            "average_score": round(self.average_score, 2),
            "results": [r.to_dict() for r in self.results],
        }
