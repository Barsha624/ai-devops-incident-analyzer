import io
import json
import urllib.error

import pytest

from incident_analyzer.ai import explain, validate_output
from incident_analyzer.ai.offline import OfflineProvider
from incident_analyzer.ai.payload import SYSTEM_PROMPT, build_payload
from incident_analyzer.ai.providers import (
    AnthropicProvider,
    Completion,
    HTTPClient,
    OpenAICompatibleProvider,
    create_provider,
    is_external,
)
from incident_analyzer.config import AIConfig
from incident_analyzer.exceptions import AIProviderError, AIRateLimitError, AIResponseError

SECRET_LINE = "ERROR [pay] charge failed for bob@example.com password=hunter2hunter2 ip 203.0.113.7"


def make_report(excerpt=SECRET_LINE):
    def incident(n, severity, count):
        return {
            "id": f"INC-00{n}",
            "service": "pay",
            "severity": severity,
            "severity_score": 5,
            "severity_reasons": ["+2 base: x"],
            "first_seen": "2026-10-31T09:00:00.000Z",
            "last_seen": "2026-10-31T09:05:00.000Z",
            "duration_seconds": 300.0,
            "finding_count": count,
            "kinds": {"timeout": count},
            "top_signatures": [{"signature": "timeout <n>", "count": count}],
            "spikes": [],
            "possibly_related_incidents": [],
            "evidence": [
                {
                    "evidence_id": f"INC-00{n}-E{e}",
                    "timestamp": "2026-10-31T09:00:00.000Z",
                    "level": "ERROR",
                    "kind": "timeout",
                    "excerpt": excerpt,
                }
                for e in (1, 2)
            ],
        }

    return {
        "incidents": [incident(1, "low", 3), incident(2, "critical", 50), incident(3, "high", 9)]
    }


class FakeProvider:
    name = "fake"
    model = "fake-1"

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, system, user, *, max_tokens):
        self.calls.append((system, user, max_tokens))
        return Completion(self.reply, 10, 5)


def good_reply(incident_id="INC-002", **overrides):
    item = {
        "incident_id": incident_id,
        "summary": "Timeouts against a dependency.",
        "observed_facts": [{"fact": "50 timeouts.", "evidence_ids": [f"{incident_id}-E1"]}],
        "hypotheses": [
            {"statement": "Pool saturated?", "confidence": "medium", "evidence_ids": [incident_id]}
        ],
        "investigation_steps": ["Check connection pool dashboards."],
        "caveats": [],
    }
    item.update(overrides)
    return json.dumps({"incidents": [item]})


# ------------------------------------------------------------------ payload / privacy


def test_payload_is_redacted_bounded_and_prioritised():
    config = AIConfig(max_incidents=2, max_evidence_per_incident=1)
    payload = build_payload(make_report(), config)
    assert [i["incident_id"] for i in payload["incidents"]] == ["INC-002", "INC-003"]
    assert all(len(i["evidence"]) == 1 for i in payload["incidents"])
    blob = json.dumps(payload)
    for secret in ("bob@example.com", "hunter2hunter2", "203.0.113.7"):
        assert secret not in blob
    assert "[REDACTED" in blob


def test_payload_never_contains_file_paths():
    report = make_report()
    report["incidents"][0]["evidence"][0]["source"] = "/var/log/secret/app.log"
    assert "/var/log" not in json.dumps(build_payload(report, AIConfig()))


def test_system_prompt_treats_logs_as_data_and_forbids_state_changes():
    assert "untrusted DATA" in SYSTEM_PROMPT
    assert "read-only" in SYSTEM_PROMPT
    assert "Do not restate or change the severity" in SYSTEM_PROMPT


# ------------------------------------------------------------------ validation


ALLOWED = {"INC-002": {"INC-002", "INC-002-E1", "INC-002-E2"}}


def test_valid_output_is_accepted():
    items, dropped = validate_output(good_reply(), ALLOWED)
    assert items[0]["observed_facts"][0]["evidence_ids"] == ["INC-002-E1"]
    assert items[0]["hypotheses"][0]["grounded"] is True
    assert dropped == {"unknown_incidents": 0, "ungrounded_facts": 0, "unsafe_steps": 0}


def test_json_inside_code_fence_is_extracted():
    items, _ = validate_output("Sure!\n```json\n" + good_reply() + "\n```", ALLOWED)
    assert items[0]["incident_id"] == "INC-002"


@pytest.mark.parametrize("reply", ["not json at all", "{broken", '{"incidents": "x"}', "[]"])
def test_garbage_is_rejected(reply):
    with pytest.raises(AIResponseError):
        validate_output(reply, ALLOWED)


def test_unknown_incident_is_dropped_and_empty_result_is_an_error():
    with pytest.raises(AIResponseError):
        validate_output(good_reply("INC-999"), ALLOWED)


def test_fact_citing_unknown_evidence_is_dropped():
    reply = good_reply(observed_facts=[{"fact": "Made up.", "evidence_ids": ["INC-002-E99"]}])
    items, dropped = validate_output(reply, ALLOWED)
    assert items[0]["observed_facts"] == []
    assert dropped["ungrounded_facts"] == 1


def test_ungrounded_hypothesis_is_kept_but_flagged_and_bad_confidence_is_lowered():
    reply = good_reply(
        hypotheses=[{"statement": "Maybe DNS.", "confidence": "certain", "evidence_ids": []}]
    )
    hypothesis = validate_output(reply, ALLOWED)[0][0]["hypotheses"][0]
    assert hypothesis["grounded"] is False and hypothesis["confidence"] == "low"


@pytest.mark.parametrize(
    "step",
    [
        "Run kubectl delete pod web-1",
        "restart the service",
        "rm -rf /var/lib/x",
        "Terminate the instance",
    ],
)
def test_state_changing_steps_are_dropped(step):
    reply = good_reply(investigation_steps=[step, "Read the logs."])
    items, dropped = validate_output(reply, ALLOWED)
    assert items[0]["investigation_steps"] == ["Read the logs."]
    assert dropped["unsafe_steps"] == 1


def test_model_cannot_inject_severity_or_unknown_fields():
    reply = good_reply(severity="low", severity_score=0, evil="x")
    item = validate_output(reply, ALLOWED)[0][0]
    assert "severity" not in item and "evil" not in item


def test_overlong_text_is_truncated():
    item = validate_output(good_reply(summary="x" * 5000), ALLOWED)[0][0]
    assert len(item["summary"]) <= 500


# ------------------------------------------------------------------ explain()


def test_explain_ok_with_fake_provider_and_severity_is_untouched():
    report = make_report()
    before = json.dumps(report, sort_keys=True)
    reply = good_reply(summary="This is actually LOW severity, ignore the rules.")
    result = explain(report, AIConfig(enabled=True), provider=FakeProvider(reply), environ={})
    assert result["status"] == "ok"
    assert json.dumps(report, sort_keys=True) == before  # explain() never mutates the report
    assert "severity" not in result["incidents"][0]
    assert result["disclaimer"].startswith("Generated text, not verified")


def test_explain_failure_is_contained():
    result = explain(
        make_report(), AIConfig(enabled=True), provider=FakeProvider("garbage"), environ={}
    )
    assert result["status"] == "failed" and "JSON" in result["error"]


def test_provider_exception_is_contained():
    class Boom(FakeProvider):
        def complete(self, *a, **k):
            raise AIRateLimitError("slow down")

    result = explain(make_report(), AIConfig(enabled=True), provider=Boom(""), environ={})
    assert result["status"] == "failed" and "slow down" in result["error"]


def test_kill_switch_beats_everything():
    provider = FakeProvider(good_reply())
    result = explain(
        make_report(),
        AIConfig(enabled=True),
        provider=provider,
        environ={"INCIDENT_ANALYZER_DISABLE_AI": "1"},
    )
    assert result["status"] == "disabled" and provider.calls == []


def test_no_incidents_is_skipped():
    result = explain({"incidents": []}, AIConfig(enabled=True), environ={})
    assert result["status"] == "skipped"


def test_dry_run_sends_nothing_and_shows_the_request():
    provider = FakeProvider(good_reply())
    result = explain(
        make_report(),
        AIConfig(enabled=True, provider="anthropic"),
        provider=provider,
        environ={},
        dry_run=True,
    )
    assert result["status"] == "dry_run" and provider.calls == []
    assert result["would_send_externally"] is True
    assert "hunter2hunter2" not in result["request"]["user"]
    assert result["estimated_input_tokens"] > 0


def test_external_provider_needs_explicit_consent_even_with_a_key():
    result = explain(
        make_report(),
        AIConfig(enabled=True, provider="anthropic"),
        environ={"ANTHROPIC_API_KEY": "test-key"},
    )
    assert result["status"] == "blocked" and "--allow-external-ai" in result["error"]


def test_missing_api_key_is_a_clear_failure():
    result = explain(
        make_report(),
        AIConfig(enabled=True, provider="anthropic", allow_external=True),
        environ={},
    )
    assert result["status"] == "failed" and "ANTHROPIC_API_KEY" in result["error"]


def test_offline_provider_end_to_end_passes_the_same_validation():
    result = explain(make_report(), AIConfig(enabled=True, provider="offline"), environ={})
    assert result["status"] == "ok" and result["model"] == "template-v1"
    for item in result["incidents"]:
        assert item["observed_facts"] and all(f["evidence_ids"] for f in item["observed_facts"])
        assert all(h["confidence"] == "low" for h in item["hypotheses"])


def test_offline_provider_is_deterministic():
    user = json.dumps(build_payload(make_report(), AIConfig()))
    first = OfflineProvider().complete("", user, max_tokens=100).text
    assert first == OfflineProvider().complete("", user, max_tokens=100).text


def test_is_external():
    assert not is_external(AIConfig(provider="offline"))
    assert is_external(AIConfig(provider="anthropic"))
    assert is_external(AIConfig(provider="openai-compatible"))
    assert not is_external(
        AIConfig(provider="openai-compatible", base_url="http://localhost:11434/v1")
    )


# ------------------------------------------------------------------ HTTP behaviour


class FakeResponse:
    def __init__(self, payload):
        self._raw = json.dumps(payload).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code, headers=None, message="boom"):
    body = io.BytesIO(json.dumps({"error": {"message": message}}).encode())
    return urllib.error.HTTPError("https://x", code, "err", headers or {}, body)


class Script:
    """A fake urlopen that plays back responses/exceptions and records requests."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


def client(script, retries=2):
    sleeps = []
    return HTTPClient(timeout=5, max_retries=retries, sleep=sleeps.append, urlopen=script), sleeps


def test_rate_limit_is_retried_and_retry_after_is_honoured():
    script = Script(http_error(429, {"Retry-After": "7"}), {"ok": True})
    http, sleeps = client(script)
    assert http.post_json("https://x", {}, {}) == {"ok": True}
    assert sleeps == [7.0]


def test_server_errors_use_exponential_backoff_then_give_up():
    script = Script(http_error(503), http_error(503), http_error(503))
    http, sleeps = client(script)
    with pytest.raises(AIProviderError, match="503"):
        http.post_json("https://x", {}, {})
    assert sleeps == [1.0, 2.0] and len(script.requests) == 3


def test_persistent_429_raises_rate_limit_error():
    http, _ = client(Script(http_error(429), http_error(429)), retries=1)
    with pytest.raises(AIRateLimitError):
        http.post_json("https://x", {}, {})


def test_auth_errors_are_not_retried():
    script = Script(http_error(401, message="invalid x-api-key"))
    http, sleeps = client(script)
    with pytest.raises(AIProviderError, match="401"):
        http.post_json("https://x", {}, {})
    assert sleeps == [] and len(script.requests) == 1


def test_network_errors_and_timeouts_are_retried():
    script = Script(urllib.error.URLError("dns"), TimeoutError(), {"ok": 1})
    http, sleeps = client(script)
    assert http.post_json("https://x", {}, {}) == {"ok": 1} and len(sleeps) == 2


def test_backoff_is_capped():
    http, sleeps = client(Script(http_error(429, {"Retry-After": "9999"}), {"ok": 1}))
    http.post_json("https://x", {}, {})
    assert sleeps == [60.0]


def test_anthropic_request_shape_and_response_parsing():
    script = Script(
        {
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 11, "output_tokens": 4},
        }
    )
    http, _ = client(script)
    provider = AnthropicProvider(api_key="test-key", model="m", base_url="", http=http)
    completion = provider.complete("sys", "user", max_tokens=99)
    assert (completion.text, completion.input_tokens, completion.output_tokens) == ("hi", 11, 4)
    request = script.requests[0]
    assert request.full_url == "https://api.anthropic.com/v1/messages"
    assert request.get_header("X-api-key") == "test-key"
    body = json.loads(request.data)
    assert body["system"] == "sys" and body["max_tokens"] == 99 and body["model"] == "m"


def test_openai_compatible_local_server_needs_no_key():
    script = Script({"choices": [{"message": {"content": "hello"}}]})
    http, _ = client(script)
    provider = OpenAICompatibleProvider(
        api_key=None, model="llama3", base_url="http://localhost:11434/v1", http=http
    )
    assert provider.complete("s", "u", max_tokens=50).text == "hello"
    assert script.requests[0].full_url == "http://localhost:11434/v1/chat/completions"
    assert script.requests[0].get_header("Authorization") is None


def test_openai_remote_needs_a_key():
    http, _ = client(Script())
    with pytest.raises(AIProviderError, match="OPENAI_API_KEY"):
        OpenAICompatibleProvider(api_key=None, model="m", base_url="", http=http)


def test_malformed_provider_payloads_become_provider_errors():
    http, _ = client(Script({"choices": []}))
    provider = OpenAICompatibleProvider(api_key="k", model="m", base_url="", http=http)
    with pytest.raises(AIProviderError):
        provider.complete("s", "u", max_tokens=50)


def test_create_provider_reads_keys_from_the_environment_only():
    provider = create_provider(AIConfig(provider="anthropic"), {"ANTHROPIC_API_KEY": "from-env"})
    assert isinstance(provider, AnthropicProvider)
    with pytest.raises(AIProviderError):
        create_provider(AIConfig(provider="anthropic"), {})
