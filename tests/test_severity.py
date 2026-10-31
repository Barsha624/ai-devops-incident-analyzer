from helpers import at, make_event
from incident_analyzer.detection import detect
from incident_analyzer.incidents import Incident, Severity
from incident_analyzer.models import Level
from incident_analyzer.severity import SeverityRules, assess, attach_spikes, score_to_severity
from incident_analyzer.spikes import SpikePeriod


def incident(times, service="svc", **kwargs):
    findings = [
        detect(make_event(t=t, service=service, line_no=i, **kwargs)) for i, t in enumerate(times)
    ]
    return Incident(service=service, findings=findings, id="INC-001")


def spike(service="svc", start=0, end=60, peak=20):
    return SpikePeriod(
        service=service,
        start=at(start),
        end=at(end),
        peak_count=peak,
        total_count=peak,
        baseline=1.0,
        threshold=10.0,
        window_seconds=60,
    )


def scored(inc, log_end=None, rules=None):
    assess(inc, log_end=log_end, gap_seconds=300, rules=rules)
    return inc


class TestPoints:
    def test_small_error_log_incident_is_low(self):
        inc = scored(incident([0, 1, 2]))
        assert inc.severity_score == 1
        assert inc.severity is Severity.LOW
        assert inc.severity_reasons == ["+1 base: most serious finding kind is error_log"]

    def test_http_5xx_base_points(self):
        inc = scored(incident([0, 1, 2], status=502))
        assert inc.severity_score == 2

    def test_volume_steps(self):
        assert scored(incident(range(5), status=502)).severity_score == 2 + 1
        assert scored(incident(range(20), status=502)).severity_score == 2 + 2
        assert scored(incident(range(100), status=502)).severity_score == 2 + 3

    def test_duration_point_only_when_long_enough(self):
        short = scored(incident([0, 100, 200], status=502))
        long = scored(incident([0, 150, 300], status=502))
        assert short.severity_score == 2
        assert long.severity_score == 3
        assert any(r.startswith("+1 duration") for r in long.severity_reasons)

    def test_spike_point(self):
        inc = incident([0, 1, 2], status=502)
        inc.spikes = [spike()]
        assert scored(inc).severity_score == 3

    def test_critical_level_point(self):
        inc = incident([0, 1, 2], level=Level.CRITICAL, message="fatal")
        scored(inc)
        assert inc.severity_score == 1 + 2

    def test_variety_point(self):
        findings = [
            detect(make_event(t=0, status=502)),
            detect(make_event(t=1, message="plain error")),
            detect(make_event(t=2, message="plain error")),
        ]
        inc = Incident(service="svc", findings=findings, id="INC-001")
        scored(inc)
        assert inc.severity_score == 2 + 1
        assert any("variety" in r for r in inc.severity_reasons)

    def test_critical_service_point(self):
        inc = incident([0, 1, 2], status=502)
        rules = SeverityRules(critical_services=frozenset({"svc"}))
        assert scored(inc, rules=rules).severity_score == 3

    def test_ongoing_point_when_incident_reaches_log_end(self):
        reaching = scored(incident([0, 1, 2], status=502), log_end=at(100))
        ended_early = scored(incident([0, 1, 2], status=502), log_end=at(5000))
        assert reaching.severity_score == 3
        assert ended_early.severity_score == 2

    def test_undated_incident_gets_no_time_based_points(self):
        findings = [detect(make_event(t=None, status=502, line_no=i)) for i in range(3)]
        inc = Incident(service="svc", findings=findings, id="INC-001")
        scored(inc, log_end=at(100))
        assert inc.severity_score == 2


class TestThresholds:
    def test_score_to_severity_boundaries(self):
        rules = SeverityRules()
        expected = {
            0: "low",
            2: "low",
            3: "medium",
            4: "medium",
            5: "high",
            6: "high",
            7: "critical",
        }
        for score, label in expected.items():
            assert score_to_severity(score, rules).label == label

    def test_every_point_has_a_reason(self):
        inc = incident(range(0, 700, 7), status=502)  # 100 findings, 693 s
        inc.spikes = [spike()]
        scored(inc, log_end=at(700))
        assert len(inc.severity_reasons) >= 4
        total = sum(int(r.split()[0]) for r in inc.severity_reasons)
        assert total == inc.severity_score


class TestAttachSpikes:
    def test_only_overlapping_spikes_of_same_service_attach(self):
        inc = incident([100, 110, 120], service="a", status=502)
        spikes = [
            spike(service="a", start=60, end=120),
            spike(service="a", start=1000, end=1060),
            spike(service="b", start=60, end=120),
        ]
        attach_spikes([inc], spikes)
        assert inc.spikes == [spikes[0]]
