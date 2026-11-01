from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from typing import Any

from incident_analyzer.ai.payload import (
    SYSTEM_PROMPT,
    build_payload,
    estimate_tokens,
    payload_to_message,
)
from incident_analyzer.ai.providers import Provider, create_provider, is_external
from incident_analyzer.config import AIConfig
from incident_analyzer.exceptions import AIConsentError, AIError, AIResponseError

logger = logging.getLogger(__name__)

KILL_SWITCH_ENV = "INCIDENT_ANALYZER_DISABLE_AI"
DISCLAIMER = (
    "Generated text, not verified. Severity, counts, timestamps and evidence elsewhere in this "
    "report come from deterministic rules; this section never changes them, and no suggested "
    "step is executed by this tool."
)
CONFIDENCE_LEVELS = ("low", "medium", "high")
MAX_ITEMS = 8
MAX_TEXT = 500

_MUTATING_STEP = re.compile(
    r"\b(rm\s+-|delete|drop\s+(table|database)|truncate|terminate|kill(all)?|reboot|shutdown"
    r"|restart|rollback|roll\s+back|scale\s+(up|down|in|out)|force[- ]push|update-service"
    r"|modify-db|stop-instances)\b",
    re.IGNORECASE,
)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _result(status: str, config: AIConfig, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "provider": config.provider,
        "model": config.model,
        "disclaimer": DISCLAIMER,
        "error": None,
        "incidents": [],
    }
    result.update(extra)
    return result


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned[:MAX_TEXT] if cleaned else None


def _refs(value: Any, allowed: set[str]) -> list[str]:
    if not isinstance(value, list):
        return []
    return [r for r in value if isinstance(r, str) and r in allowed][:MAX_ITEMS]


def _extract_json(text: str) -> Any:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise AIResponseError("model reply contains no JSON object")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AIResponseError(f"model reply is not valid JSON: {exc.msg}") from exc


def validate_output(
    text: str, allowed_refs: Mapping[str, set[str]]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse and sanitise model output.

    ``allowed_refs`` maps each incident id we asked about to the ids it may cite (its evidence ids
    plus the incident id itself). Returns ``(explanations, counters_of_what_was_dropped)``.
    """
    data = _extract_json(text)
    items = data.get("incidents") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise AIResponseError('model JSON has no "incidents" list')

    dropped = {"unknown_incidents": 0, "ungrounded_facts": 0, "unsafe_steps": 0}
    explained: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        incident_id = item.get("incident_id") if isinstance(item, dict) else None
        if (
            not isinstance(incident_id, str)
            or incident_id not in allowed_refs
            or incident_id in seen
        ):
            dropped["unknown_incidents"] += 1
            continue
        seen.add(incident_id)
        allowed = allowed_refs[incident_id]
        summary = _text(item.get("summary"))
        if summary is None:
            raise AIResponseError(f"{incident_id}: missing summary")

        facts = []
        for fact in (item.get("observed_facts") or [])[:MAX_ITEMS]:
            statement = _text(fact.get("fact")) if isinstance(fact, dict) else None
            refs = _refs(fact.get("evidence_ids"), allowed) if isinstance(fact, dict) else []
            if statement and refs:
                facts.append({"fact": statement, "evidence_ids": refs})
            else:
                dropped["ungrounded_facts"] += 1

        hypotheses = []
        for hyp in (item.get("hypotheses") or [])[:MAX_ITEMS]:
            statement = _text(hyp.get("statement")) if isinstance(hyp, dict) else None
            if not statement:
                continue
            confidence = hyp.get("confidence")
            refs = _refs(hyp.get("evidence_ids"), allowed)
            hypotheses.append(
                {
                    "statement": statement,
                    "confidence": confidence if confidence in CONFIDENCE_LEVELS else "low",
                    "evidence_ids": refs,
                    "grounded": bool(refs),
                }
            )

        steps = []
        for step in (item.get("investigation_steps") or [])[:MAX_ITEMS]:
            step_text = _text(step)
            if step_text is None:
                continue
            if _MUTATING_STEP.search(step_text):
                dropped["unsafe_steps"] += 1
                continue
            steps.append(step_text)

        caveats = [c for c in (_text(c) for c in (item.get("caveats") or [])[:MAX_ITEMS]) if c]
        explained.append(
            {
                "incident_id": incident_id,
                "summary": summary,
                "observed_facts": facts,
                "hypotheses": hypotheses,
                "investigation_steps": steps,
                "caveats": caveats,
            }
        )
    if not explained:
        raise AIResponseError("model reply did not explain any of the supplied incidents")
    return explained, dropped


def explain(
    report: dict[str, Any],
    config: AIConfig,
    *,
    provider: Provider | None = None,
    environ: Mapping[str, str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Return the ``report["ai"]`` block. Never raises for provider or model problems."""
    env = os.environ if environ is None else environ
    if _truthy(env.get(KILL_SWITCH_ENV)):
        return _result("disabled", config, error=f"AI disabled by {KILL_SWITCH_ENV}")

    payload = build_payload(report, config)
    if not payload["incidents"]:
        return _result("skipped", config, error="no incidents to explain")
    user = payload_to_message(payload)
    external = is_external(config)

    if dry_run:
        return _result(
            "dry_run",
            config,
            request={"system": SYSTEM_PROMPT, "user": user},
            estimated_input_tokens=estimate_tokens(SYSTEM_PROMPT, user),
            would_send_externally=external,
        )

    allowed = {
        i["incident_id"]: {i["incident_id"], *(e["evidence_id"] for e in i["evidence"])}
        for i in payload["incidents"]
    }
    try:
        if provider is None:
            if external and not config.allow_external:
                raise AIConsentError(
                    f"provider {config.provider!r} would send data to an external service. "
                    "Review it with --ai-dry-run, then opt in with --allow-external-ai "
                    "(or ai.allow_external = true)"
                )
            provider = create_provider(config, env)
        completion = provider.complete(SYSTEM_PROMPT, user, max_tokens=config.max_tokens)
        items, dropped = validate_output(completion.text, allowed)
    except AIConsentError as exc:
        return _result("blocked", config, error=str(exc))
    except AIError as exc:
        logger.warning("ai_failed", extra={"event": "ai_failed", "error": str(exc)})
        return _result("failed", config, error=str(exc))

    logger.info("ai_explained", extra={"event": "ai_explained", "provider": provider.name})
    return _result(
        "ok",
        config,
        provider=provider.name,
        model=provider.model,
        incidents=items,
        usage={
            "estimated_input_tokens": estimate_tokens(SYSTEM_PROMPT, user),
            "input_tokens": completion.input_tokens,
            "output_tokens": completion.output_tokens,
        },
        dropped=dropped,
    )
