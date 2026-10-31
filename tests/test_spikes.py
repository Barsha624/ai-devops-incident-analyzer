from datetime import timedelta

from helpers import at, make_event
from incident_analyzer.detection import detect
from incident_analyzer.spikes import detect_spikes, median_with_zeros


def findings_at(times, service="svc"):
    return [detect(make_event(t=t, service=service, message="boom")) for t in times]


class TestMedianWithZeros:
    def test_mostly_zero_windows_give_zero_baseline(self):
        assert median_with_zeros([1, 2], total_windows=10) == 0.0

    def test_all_windows_present(self):
        assert median_with_zeros([1, 2, 3], total_windows=3) == 2.0

    def test_no_data(self):
        assert median_with_zeros([], total_windows=0) == 0.0


class TestSpikes:
    def test_burst_in_quiet_log_is_a_spike(self):
        # 1 error per minute for 30 minutes, then 25 errors inside minute 20.
        quiet = findings_at([m * 60 for m in range(30)])
        burst = findings_at([20 * 60 + s for s in range(25)])
        spikes = detect_spikes(
            quiet + burst, log_start=at(0), log_end=at(30 * 60), window_seconds=60, min_count=10
        )
        assert len(spikes) == 1
        spike = spikes[0]
        assert spike.service == "svc"
        assert spike.start == at(20 * 60)
        assert spike.end == at(21 * 60)
        assert spike.peak_count == 26
        assert spike.baseline == 1.0

    def test_steady_error_rate_is_not_a_spike(self):
        findings = findings_at([m * 60 + s for m in range(30) for s in (0, 20, 40)])
        assert detect_spikes(findings, log_start=at(0), log_end=at(30 * 60)) == []

    def test_below_min_count_is_not_a_spike(self):
        burst = findings_at([s for s in range(8)])
        assert detect_spikes(burst, log_start=at(0), log_end=at(600), min_count=10) == []

    def test_consecutive_windows_merge_into_one_period(self):
        burst = findings_at([s for s in range(120) if s % 4 == 0] + [60 + s for s in range(15)])
        spikes = detect_spikes(
            burst, log_start=at(0), log_end=at(3600), window_seconds=60, min_count=10
        )
        assert len(spikes) == 1
        assert spikes[0].end - spikes[0].start == timedelta(minutes=2)

    def test_services_are_evaluated_independently(self):
        a = findings_at([s for s in range(30)], service="a")
        b = findings_at([s * 60 for s in range(5)], service="b")
        spikes = detect_spikes(a + b, log_start=at(0), log_end=at(3600), min_count=10)
        assert [s.service for s in spikes] == ["a"]

    def test_findings_without_timestamps_are_ignored(self):
        undated = [detect(make_event(t=None)) for _ in range(50)]
        assert detect_spikes(undated, log_start=at(0), log_end=at(60)) == []

    def test_missing_log_range_returns_empty(self):
        assert detect_spikes(findings_at([0, 1, 2]), log_start=None, log_end=None) == []
