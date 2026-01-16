# backend/risk_scoring.py

"""
Rule-based risk scoring for DissoFinito.

This module is intentionally simple and self-contained so it can later
be replaced by a proper ML-based classifier without touching the rest
of the backend.
"""

from typing import Dict, Iterable, List, Tuple

from models import Finding  # type: ignore[import]


SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
}


def severity_counts(findings: Iterable[Finding]) -> Dict[str, int]:
    """
    Count findings per severity level.

    Returns a dict with keys: "critical", "high", "medium", "low".
    Unknown severities are grouped into "low".
    """
    counts: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for f in findings:
        sev = (f.severity or "").lower()
        if sev not in counts:
            sev = "low"
        counts[sev] += 1

    return counts


def compute_risk_score(findings: List[Finding]) -> Tuple[float, str]:
    """
    Compute a simple rule-based risk score and band.

    raw_score = 10*critical + 5*high + 3*medium + 1*low
    normalized_score = min(raw_score, 100)

    Band mapping:
      0–20   -> "Low"
      21–50  -> "Medium"
      51–80  -> "High"
      81–100 -> "Critical"
    """
    counts = severity_counts(findings)

    raw_score = (
        SEVERITY_WEIGHTS["critical"] * counts["critical"]
        + SEVERITY_WEIGHTS["high"] * counts["high"]
        + SEVERITY_WEIGHTS["medium"] * counts["medium"]
        + SEVERITY_WEIGHTS["low"] * counts["low"]
    )

    normalized_score = float(min(raw_score, 100))

    if normalized_score <= 20:
        band = "Low"
    elif normalized_score <= 50:
        band = "Medium"
    elif normalized_score <= 80:
        band = "High"
    else:
        band = "Critical"

    return normalized_score, band
