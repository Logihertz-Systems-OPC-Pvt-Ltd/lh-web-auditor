"""Tests for scoring and grading logic."""

from __future__ import annotations

from lh_web_auditor.models import Category, Finding, Severity
from lh_web_auditor.scoring import calculate_grade, calculate_score


def test_grade_mapping() -> None:
    """Verify grade letter thresholds."""
    assert calculate_grade(100) == "A+"
    assert calculate_grade(95) == "A+"
    assert calculate_grade(94) == "A"
    assert calculate_grade(85) == "A"
    assert calculate_grade(84) == "B"
    assert calculate_grade(70) == "B"
    assert calculate_grade(69) == "C"
    assert calculate_grade(50) == "C"
    assert calculate_grade(49) == "D"
    assert calculate_grade(30) == "D"
    assert calculate_grade(29) == "F"
    assert calculate_grade(0) == "F"


def test_perfect_score_no_findings() -> None:
    """No findings should yield 100 points and A+ grade."""
    score, grade = calculate_score([])
    assert score == 100
    assert grade == "A+"


def test_penalty_deductions() -> None:
    """Test deductions per severity level."""
    findings = [
        Finding(
            id="CRIT-1",
            title="Crit",
            category=Category.CORS,
            severity=Severity.CRITICAL,
            description="desc",
            evidence="ev",
            recommendation="rec",
        ),
        Finding(
            id="HIGH-1",
            title="High",
            category=Category.HEADERS,
            severity=Severity.HIGH,
            description="desc",
            evidence="ev",
            recommendation="rec",
        ),
        Finding(
            id="MED-1",
            title="Med",
            category=Category.COOKIES,
            severity=Severity.MEDIUM,
            description="desc",
            evidence="ev",
            recommendation="rec",
        ),
        Finding(
            id="LOW-1",
            title="Low",
            category=Category.HEADERS,
            severity=Severity.LOW,
            description="desc",
            evidence="ev",
            recommendation="rec",
        ),
        Finding(
            id="INFO-1",
            title="Info",
            category=Category.DISCLOSURE,
            severity=Severity.INFO,
            description="desc",
            evidence="ev",
            recommendation="rec",
        ),
    ]
    # Deductions: 25 + 15 + 8 + 4 + 0 = 52. 100 - 52 = 48 -> Grade D
    score, grade = calculate_score(findings)
    assert score == 48
    assert grade == "D"


def test_score_floor_zero() -> None:
    """Extreme deductions should clamp at 0 and grade F."""
    findings = [
        Finding(
            id=f"CRIT-{i}",
            title=f"Crit {i}",
            category=Category.CORS,
            severity=Severity.CRITICAL,
            description="desc",
            evidence="ev",
            recommendation="rec",
        )
        for i in range(10)
    ]
    # 10 * 25 = 250 penalty -> score should be 0
    score, grade = calculate_score(findings)
    assert score == 0
    assert grade == "F"
