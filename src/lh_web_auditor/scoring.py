"""Security posture score calculation and grading logic."""

from __future__ import annotations

from collections.abc import Sequence

from lh_web_auditor.models import Finding, Severity

# Weighted penalties per severity level
PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


def calculate_grade(score: int) -> str:
    """Map a numerical security score (0-100) to an academic letter grade."""
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def calculate_score(findings: Sequence[Finding]) -> tuple[int, str]:
    """Calculate the aggregated security score (0-100) and letter grade from findings.

    Args:
        findings: Sequence of observed security findings.

    Returns:
        A tuple of (numerical_score, letter_grade).
    """
    total_penalty = sum(PENALTIES.get(f.severity, 0) for f in findings)
    raw_score = 100 - total_penalty
    score = max(0, min(100, raw_score))
    grade = calculate_grade(score)
    return score, grade
