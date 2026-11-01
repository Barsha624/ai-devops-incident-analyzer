from __future__ import annotations

import json

from incident_analyzer.ai.providers import Completion

_HYPOTHESES = {
    "http_5xx": "The service (or a dependency behind it) is failing requests; a recent change "
    "or an unhealthy dependency may be responsible.",
    "timeout": "A downstream dependency or shared resource (connection pool, thread pool, "
    "network path) may be slow or saturated.",
    "exception": "Repeated exceptions often come from a code defect or unexpected input data, "
    "possibly introduced by a recent deploy or configuration change.",
    "error_log": "The service logs errors that match no more specific rule; the evidence lines "
    "should name the cause.",
}

_STEPS = {
    "http_5xx": "Check the service's error-rate and latency dashboards around the incident start.",
    "timeout": "Check saturation of the called dependency (connections in use, queue depth, CPU).",
    "exception": "Compare the incident start time with your deploy and config-change history.",
    "error_log": "Read the evidence lines and the log context just before the first error.",
}


def _explain_one(incident: dict[str, object]) -> dict[str, object]:
    evidence = incident["evidence"]
    assert isinstance(evidence, list)
    kinds = incident["finding_kinds"]
    assert isinstance(kinds, dict)
    incident_id = str(incident["incident_id"])
    kind_text = ", ".join(f"{k}={v}" for k, v in kinds.items())
    top_kind = next(iter(kinds), "error_log")

    facts = [
        {
            "fact": (
                f"{incident['finding_count']} findings ({kind_text}) between "
                f"{incident['first_seen']} and {incident['last_seen']}."
            ),
            "evidence_ids": [incident_id],
        }
    ]
    first_ids = [e["evidence_id"] for e in evidence[:1] if isinstance(e, dict)]
    for item in evidence[:3]:
        if isinstance(item, dict):
            facts.append(
                {
                    "fact": f"At {item['timestamp']} a finding of kind {item['kind']} was logged: "
                    f"{str(item['excerpt'])[:140]}",
                    "evidence_ids": [item["evidence_id"]],
                }
            )

    steps = [_STEPS.get(top_kind, _STEPS["error_log"])]
    related = incident.get("possibly_related_incidents")
    if isinstance(related, list) and related:
        steps.append(
            f"Compare start times with {', '.join(str(r) for r in related)}: they overlap in time, "
            "so check which one started first. Overlap alone does not prove causation."
        )
    return {
        "incident_id": incident_id,
        "summary": (
            f"{incident['service']} logged {incident['finding_count']} related findings; "
            f"the rule engine rated this {incident['severity']} "
            f"(score {incident['severity_score']})."
        ),
        "observed_facts": facts,
        "hypotheses": [
            {
                "statement": _HYPOTHESES.get(top_kind, _HYPOTHESES["error_log"]),
                "confidence": "low",
                "evidence_ids": first_ids or [incident_id],
            }
        ],
        "investigation_steps": steps,
        "caveats": [
            "Template output from the offline provider: generic, not tailored to your system."
        ],
    }


class OfflineProvider:
    name = "offline"
    model = "template-v1"

    def complete(self, system: str, user: str, *, max_tokens: int) -> Completion:
        payload = json.loads(user)
        return Completion(
            json.dumps({"incidents": [_explain_one(i) for i in payload["incidents"]]})
        )
