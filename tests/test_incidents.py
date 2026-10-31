from helpers import make_event
from incident_analyzer.detection import detect
from incident_analyzer.incidents import group_findings
from incident_analyzer.models import Level


def findings(times, service="svc", **kwargs):
    return [
        detect(make_event(t=t, service=service, line_no=i, **kwargs)) for i, t in enumerate(times)
    ]


def group(items, gap=300, min_events=3, slack=60):
    return group_findings(
        items, gap_seconds=gap, min_events=min_events, related_slack_seconds=slack
    )


class TestGrouping:
    def test_close_findings_form_one_incident(self):
        result = group(findings([0, 10, 20, 30]))
        assert len(result.incidents) == 1
        assert result.incidents[0].count == 4
        assert result.incidents[0].id == "INC-001"

    def test_large_gap_splits_incidents(self):
        result = group(findings([0, 10, 20, 1000, 1010, 1020]), gap=300)
        assert [i.count for i in result.incidents] == [3, 3]
        assert [i.id for i in result.incidents] == ["INC-001", "INC-002"]

    def test_gap_exactly_at_limit_stays_together(self):
        result = group(findings([0, 300, 600]), gap=300)
        assert len(result.incidents) == 1

    def test_services_are_never_merged(self):
        items = findings([0, 1, 2], service="a") + findings([0, 1, 2], service="b")
        result = group(items)
        assert sorted(i.service for i in result.incidents) == ["a", "b"]

    def test_input_order_does_not_matter(self):
        forward = group(findings([0, 10, 20, 1000, 1010, 1020]))
        backward = group(findings([1020, 1010, 1000, 20, 10, 0]))
        assert [i.first_seen for i in forward.incidents] == [
            i.first_seen for i in backward.incidents
        ]

    def test_incidents_are_numbered_in_time_order(self):
        items = findings([500, 510, 520], service="late") + findings([0, 10, 20], service="early")
        result = group(items)
        assert [(i.id, i.service) for i in result.incidents] == [
            ("INC-001", "early"),
            ("INC-002", "late"),
        ]


class TestThreshold:
    def test_small_groups_are_counted_but_not_reported(self):
        result = group(findings([0, 10]), min_events=3)
        assert result.incidents == []
        assert result.below_threshold_groups == 1
        assert result.below_threshold_findings == 2

    def test_single_critical_log_is_always_an_incident(self):
        items = [detect(make_event(t=0, level=Level.CRITICAL, message="out of memory"))]
        result = group(items, min_events=5)
        assert len(result.incidents) == 1
        assert result.incidents[0].has_critical_level

    def test_empty_input(self):
        result = group([])
        assert result.incidents == []
        assert result.below_threshold_groups == 0


class TestUndatedFindings:
    def test_undated_findings_form_their_own_group(self):
        undated = [detect(make_event(t=None, line_no=i)) for i in range(4)]
        result = group(undated)
        assert len(result.incidents) == 1
        incident = result.incidents[0]
        assert incident.first_seen is None
        assert incident.duration_seconds is None

    def test_dated_and_undated_do_not_mix(self):
        mixed = findings([0, 1, 2]) + [detect(make_event(t=None, line_no=99)) for _ in range(3)]
        assert len(group(mixed).incidents) == 2


class TestRelatedIncidents:
    def test_overlapping_incidents_of_different_services_are_linked(self):
        items = findings([0, 30, 60], service="a") + findings([40, 70, 100], service="b")
        a, b = group(items).incidents
        assert a.related_incident_ids == [b.id]
        assert b.related_incident_ids == [a.id]

    def test_distant_incidents_are_not_linked(self):
        items = findings([0, 30, 60], service="a") + findings([5000, 5030, 5060], service="b")
        a, b = group(items).incidents
        assert a.related_incident_ids == [] and b.related_incident_ids == []

    def test_same_service_is_never_linked_to_itself(self):
        incidents = group(findings([0, 1, 2, 1000, 1001, 1002]), gap=300, slack=2000).incidents
        assert all(not i.related_incident_ids for i in incidents)


class TestIncidentProperties:
    def test_title_uses_most_common_signature(self):
        items = findings([0, 1, 2], message="timeout calling x") + findings([3], message="other")
        incident = group(items).incidents[0]
        assert incident.title == "svc: timeout calling x x3 (+1 other signature)"

    def test_duration_and_kind_counts(self):
        incident = group(findings([0, 30, 90], status=502)).incidents[0]
        assert incident.duration_seconds == 90
        assert dict(incident.kind_counts) == {"http_5xx": 3}
