# Measuring detection quality (without inventing numbers)

This project makes **no accuracy claim**. The shipped labels describe *synthetic* logs that were written
together with the rules, so a perfect score there is a **regression test**, not evidence of real-world quality.

## What is measured

```bash
incident-analyzer evaluate evaluation/synthetic-labels.json
```

A labels file lists the log files (paths are relative to the labels file) and the incidents a human says really happened (service + time range):

```json
{
  "logs": ["../samples/checkout-api.jsonl"],
  "expected_incidents": [
    {"name": "checkout 5xx burst", "service": "checkout-api",
     "start": "2026-10-31T09:13:00Z", "end": "2026-10-31T09:25:00Z"}
  ]
}
```

A detected incident **matches** an expected one when the service is the same and the time ranges overlap.

* **Recall** = expected incidents matched / expected incidents. "Did we find what really happened?"
* **Precision** = detected incidents that matched / detected incidents. "Is what we report real?"

If nothing was expected and nothing detected, both are printed as `n/a`, never as a flattering 100%.

## Building a labelled set you can trust

1. Collect 20-50 real past incidents (post-mortems, ticket history) plus **quiet periods** with no incident.
   Quiet periods are essential: without them you can never measure false positives.
2. Label from an independent source (the incident ticket), **not** from this tool's output.
3. Sanitise the logs before storing them in a repository.
4. Split into a tuning set and a held-out set. Tune thresholds only on the first, report on the second.
5. Keep old and new results side by side whenever you change a rule.

## Measuring the AI layer

Use the same discipline: a fixed set of incidents, a written rubric (does every observed fact cite evidence and
is it true? is any hypothesis presented as certain? any state-changing suggestion?), two reviewers, and a record
of model + `prompt_version`. Report the rubric results, not an impression.
