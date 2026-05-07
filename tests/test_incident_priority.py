"""
incident_priority — öncelik skoru hesaplama testleri.
"""
import pytest
from server.incident_priority import compute_priority_score


class TestComputePriorityScore:
    def test_critical_no_ti(self):
        assert compute_priority_score("critical", 0) == 80

    def test_warning_no_ti(self):
        assert compute_priority_score("warning", 0) == 50

    def test_info_no_ti(self):
        assert compute_priority_score("info", 0) == 25

    def test_critical_high_ti(self):
        """critical + AbuseIPDB ≥70 → 80×1.30 = 104 → capped at 100."""
        assert compute_priority_score("critical", 85) == 100

    def test_critical_medium_ti(self):
        """critical + AbuseIPDB ≥30 → 80×1.10 = 88."""
        assert compute_priority_score("critical", 50) == 88

    def test_warning_high_ti(self):
        """warning + AbuseIPDB ≥70 → 50×1.30 = 65."""
        assert compute_priority_score("warning", 70) == 65

    def test_warning_medium_ti(self):
        """warning + AbuseIPDB ≥30 → 50×1.10 = 55."""
        assert compute_priority_score("warning", 30) == 55

    def test_info_high_ti(self):
        """info + AbuseIPDB ≥70 → 25×1.30 = 32 (rounded)."""
        assert compute_priority_score("info", 90) == 32

    def test_unknown_severity_defaults_to_info(self):
        score = compute_priority_score("unknown_level", 0)
        assert score == 25

    def test_score_always_at_least_1(self):
        assert compute_priority_score("info", 0) >= 1

    def test_score_never_exceeds_100(self):
        assert compute_priority_score("critical", 100) <= 100

    def test_ti_threshold_boundary_70(self):
        below = compute_priority_score("warning", 69)
        at    = compute_priority_score("warning", 70)
        assert at > below

    def test_ti_threshold_boundary_30(self):
        below = compute_priority_score("warning", 29)
        at    = compute_priority_score("warning", 30)
        assert at > below
