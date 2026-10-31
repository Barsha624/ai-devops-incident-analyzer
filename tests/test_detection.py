import pytest

from helpers import make_event
from incident_analyzer.detection import (
    RULE_ERROR_LEVEL,
    RULE_EXCEPTION,
    RULE_HTTP_5XX,
    RULE_TIMEOUT,
    FindingKind,
    detect,
)
from incident_analyzer.models import Level
from incident_analyzer.signatures import normalize_message, normalize_path


class TestHttp5xx:
    @pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
    def test_5xx_statuses_are_detected(self, status):
        finding = detect(make_event(level=Level.INFO, status=status, message="request done"))
        assert finding is not None
        assert finding.kind is FindingKind.HTTP_5XX

    @pytest.mark.parametrize("status", [200, 301, 404, 429, 499, 600, None])
    def test_non_5xx_statuses_are_ignored(self, status):
        assert detect(make_event(level=Level.INFO, status=status, message="request done")) is None

    def test_signature_groups_ids_in_paths(self):
        a = detect(make_event(status=502, method="GET", path="/orders/123?x=1"))
        b = detect(make_event(status=502, method="GET", path="/orders/456"))
        assert a.signature == b.signature == "HTTP 502 GET /orders/<id>"


class TestTimeouts:
    @pytest.mark.parametrize(
        "message",
        [
            "Timeout after 30000ms calling payments-api",
            "request timed out",
            "upstream time-out",
            "context deadline exceeded",
            "connect ETIMEDOUT 10.0.0.5:5432",
            "requests.exceptions.ReadTimeout: HTTPSConnectionPool",
        ],
    )
    def test_timeout_wording_at_warn_is_detected(self, message):
        finding = detect(make_event(level=Level.WARN, message=message))
        assert finding is not None
        assert RULE_TIMEOUT in finding.rules

    def test_timeout_wording_at_info_is_not_flagged(self):
        assert detect(make_event(level=Level.INFO, message="using timeout=30s")) is None

    def test_sometimes_outage_is_not_a_timeout(self):
        assert detect(make_event(level=Level.WARN, message="sometimes outage happens")) is None

    def test_504_is_a_timeout_even_without_wording(self):
        finding = detect(make_event(level=Level.INFO, status=504, message="gateway"))
        assert finding.kind is FindingKind.HTTP_5XX
        assert set(finding.rules) == {RULE_HTTP_5XX, RULE_TIMEOUT}

    def test_timeout_signature_ignores_numbers(self):
        a = detect(make_event(level=Level.ERROR, message="Timeout after 30001ms calling 10.0.0.1"))
        b = detect(make_event(level=Level.ERROR, message="Timeout after 29987ms calling 10.0.0.9"))
        assert a.kind is FindingKind.TIMEOUT
        assert a.signature == b.signature


class TestExceptions:
    def test_exception_class_in_message(self):
        finding = detect(make_event(message="Unhandled ValueError: bad input"))
        assert finding.kind is FindingKind.EXCEPTION
        assert finding.exception_class == "ValueError"
        assert finding.signature == "ValueError"

    def test_exception_class_from_python_traceback_tail(self):
        details = (
            "Traceback (most recent call last):\n"
            '  File "app.py", line 3, in f\n'
            "ZeroDivisionError: division by zero"
        )
        finding = detect(make_event(message="request failed", details=details))
        assert finding.exception_class == "ZeroDivisionError"

    def test_dotted_java_exception(self):
        finding = detect(make_event(message="failed java.lang.NullPointerException at X"))
        assert finding.exception_class == "java.lang.NullPointerException"

    def test_warn_with_stack_trace_is_exception(self):
        details = "Traceback (most recent call last):\nKeyError: 'id'"
        finding = detect(make_event(level=Level.WARN, message="retrying", details=details))
        assert finding.kind is FindingKind.EXCEPTION

    def test_info_mentioning_exception_is_ignored(self):
        assert detect(make_event(level=Level.INFO, message="caught ValueError, recovered")) is None


class TestErrorLevel:
    def test_plain_error_is_error_log(self):
        finding = detect(make_event(message="disk almost full"))
        assert finding.kind is FindingKind.ERROR_LOG
        assert finding.rules == (RULE_ERROR_LEVEL,)

    def test_critical_is_detected(self):
        assert detect(make_event(level=Level.CRITICAL, message="out of memory")) is not None

    @pytest.mark.parametrize("level", [Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN, None])
    def test_lower_levels_without_other_signals_are_ignored(self, level):
        assert detect(make_event(level=level, message="all good")) is None


class TestPriorityAndExplainability:
    def test_http_5xx_beats_exception_and_keeps_all_rules(self):
        finding = detect(make_event(status=500, message="ValueError in handler"))
        assert finding.kind is FindingKind.HTTP_5XX
        assert finding.rules == (RULE_HTTP_5XX, RULE_EXCEPTION, RULE_ERROR_LEVEL)

    def test_event_without_timestamp_still_produces_finding(self):
        finding = detect(make_event(t=None, message="oops"))
        assert finding is not None
        assert finding.timestamp is None


class TestSignatures:
    def test_normalize_message_replaces_variable_parts(self):
        text = "user 'alice' req 3f2a9c1e-1111-2222-3333-444455556666 from 10.1.2.3:8080 took 12.5s"
        assert normalize_message(text) == "user <str> req <uuid> from <ip> took <n>s"

    def test_normalize_message_truncates(self):
        assert len(normalize_message("word " * 100)) == 120

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/orders/123", "/orders/<id>"),
            ("/orders/123/items/9?x=1", "/orders/<id>/items/<id>"),
            ("/users/3f2a9c1e-1111-2222-3333-444455556666", "/users/<id>"),
            ("/health", "/health"),
            ("/", "/"),
        ],
    )
    def test_normalize_path(self, path, expected):
        assert normalize_path(path) == expected
