# Severity rules

Severity is a **sum of documented points**. Every point added is recorded as a human-readable reason in
the report, so "why is this HIGH?" always has an answer.

| Factor | Condition | Points |
|---|---|---|
| base | most serious finding kind present: `http_5xx`, `timeout` or `exception` | +2 |
| base | only `error_log` findings | +1 |
| volume | findings >= 5 / >= 20 / >= 100 | +1 / +2 / +3 (highest step only) |
| duration | incident lasted >= 5 minutes | +1 |
| spike | an R-SPIKE period of the same service overlaps the incident | +1 |
| critical | a CRITICAL/FATAL log line is present | +2 |
| variety | two or more finding kinds | +1 |
| service | the service is listed in `critical_services` | +1 |
| ongoing | still producing findings at the end of the analysed logs | +1 |

| Score | Severity | Intended meaning |
|---|---|---|
| <= 2 | LOW | worth a look, not urgent |
| 3-4 | MEDIUM | investigate soon |
| 5-6 | HIGH | investigate now |
| >= 7 | CRITICAL | likely user-visible, sustained, or very noisy |

## Worked example (from the synthetic samples)

`INC-001  payments-worker` scored **8 = CRITICAL**:

```text
+2 base: most serious finding kind is timeout
+2 volume: 49 findings (>= 20)
+1 duration: lasted 11.7 min (>= 5 min)
+2 critical: CRITICAL/FATAL log line present
+1 variety: 2 different finding kinds
```

## What these numbers are NOT

* They are **heuristics chosen to be easy to reason about**, not values fitted to real incident data.
* They say nothing about business impact (is it the payment path or a batch job?). Use
  `critical_services` to encode that knowledge, and tune the thresholds for your own system.
* Severity here is *triage guidance for a human*, not an alerting policy. For paging decisions use
  SLO-based alerts on your metrics (error budget burn rate); use this tool to explain what happened.

## How to calibrate honestly

Build a labelled set of past incidents with the severity your on-call team actually assigned, then compare
(see [evaluation.md](evaluation.md)). Change a threshold only when the labelled data says so, and keep the old
and new results side by side.
