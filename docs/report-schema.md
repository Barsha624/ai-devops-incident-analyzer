# JSON report schema (version 1.0)

```jsonc
{
  "schema_version": "1.0",
  "tool": {"name": "ai-devops-incident-analyzer", "version": "0.1.0"},
  "generated_at": "2026-10-31T13:11:02.000Z",
  "settings": { /* the analysis thresholds used, so a result is reproducible */ },
  "inputs": [
    {"source": "samples/app.log", "lines_read": 1350, "events_parsed": 1350,
     "malformed_lines": 0, "malformed_samples": [{"line": 7, "reason": "...", "snippet": "..."}],
     "level_counts": {"INFO": 1200, "ERROR": 150}}
  ],
  "summary": {
    "events_parsed": 2646, "malformed_lines": 3, "findings": 269,
    "findings_by_kind": {"http_5xx": 177, "timeout": 84, "exception": 5, "error_log": 3},
    "incidents": 4,
    "incidents_by_severity": {"low": 0, "medium": 1, "high": 1, "critical": 2},
    "highest_severity": "critical",
    "time_range": {"start": "...", "end": "..."},
    "services": ["checkout-api", "..."],
    "below_threshold": {"groups": 1, "findings": 1}
  },
  "incidents": [
    {
      "id": "INC-001", "title": "payments-worker: ... x48",
      "service": "payments-worker",
      "severity": "critical", "severity_score": 8,
      "severity_reasons": ["+2 base: ...", "+2 volume: ..."],
      "first_seen": "...", "last_seen": "...", "duration_seconds": 705.0,
      "finding_count": 49,
      "kinds": {"timeout": 48, "error_log": 1},
      "rules_triggered": ["R-ERROR-LEVEL", "R-EXCEPTION", "R-TIMEOUT"],
      "top_signatures": [{"signature": "...", "count": 48}],
      "spikes": [{"service": "...", "start": "...", "end": "...", "peak_findings_per_window": 14,
                  "total_findings": 120, "window_seconds": 60,
                  "baseline_per_window": 0.0, "threshold_per_window": 10.0}],
      "possibly_related_incidents": ["INC-002"],
      "evidence": [
        {"evidence_id": "INC-001-E1", "source": "payments-worker.log", "line": 73,
         "timestamp": "...", "level": "ERROR", "kind": "timeout",
         "rules": ["R-TIMEOUT", "R-EXCEPTION", "R-ERROR-LEVEL"],
         "signature": "...", "excerpt": "the log line (+ trace tail), max 400 chars"}
      ]
    }
  ],
  "spikes": [ /* same shape as incident spikes, for the whole run */ ],
  "warnings": ["human-readable problems, e.g. mostly unparseable input"],
  "ai": null    // or the AI block below
}
```

## The `ai` block (only when AI was requested)

```jsonc
{
  "status": "ok",          // ok | failed | blocked | disabled | skipped | dry_run
  "provider": "offline", "model": "template-v1",
  "disclaimer": "Generated text, not verified. ...",
  "error": null,           // set when status is failed / blocked / disabled / skipped
  "incidents": [{
    "incident_id": "INC-001", "summary": "...",
    "observed_facts": [{"fact": "...", "evidence_ids": ["INC-001-E1"]}],
    "hypotheses": [{"statement": "...", "confidence": "low", "evidence_ids": ["INC-001"], "grounded": true}],
    "investigation_steps": ["read-only checks only"], "caveats": ["..."]
  }],
  "usage": {"estimated_input_tokens": 2523, "input_tokens": null, "output_tokens": null},
  "dropped": {"unknown_incidents": 0, "ungrounded_facts": 0, "unsafe_steps": 0}
}
```

`dry_run` additionally carries `request` (the exact system + user text that would be sent),
`estimated_input_tokens` and `would_send_externally`.

## Stability

`schema_version` changes when a field is removed or changes meaning; new optional fields do not bump it.
Evidence excerpts are **raw log text** unless `--redact` was used: treat the report as sensitive as the logs.
