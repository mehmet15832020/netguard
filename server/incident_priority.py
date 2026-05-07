"""
Incident öncelik skoru hesaplama.

Formül: min(100, round(severity_base × ti_factor))

severity_base : critical=80  warning=50  info=25
ti_factor     : AbuseIPDB score ≥70 → 1.30
                              ≥30 → 1.10
                              else → 1.00
"""

_SEVERITY_BASE: dict[str, int] = {
    "critical": 80,
    "warning":  50,
    "info":     25,
}


def compute_priority_score(severity: str, ti_score: int = 0) -> int:
    """
    1–100 arası öncelik skoru döner.
    ti_score: AbuseIPDB abuse confidence score (0–100), yoksa 0.
    """
    base = _SEVERITY_BASE.get(severity, 25)
    if ti_score >= 70:
        factor = 1.30
    elif ti_score >= 30:
        factor = 1.10
    else:
        factor = 1.00
    return max(1, min(100, round(base * factor)))
