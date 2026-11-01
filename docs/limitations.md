# Known limitations

Stated plainly, because a tool that hides its limits cannot be trusted.

**Detection**
* Thresholds (`min_events`, `spike_factor`, severity points) are *reasoned defaults, not calibrated* on real
  incident data. Tune them against your own labelled history ([evaluation.md](evaluation.md)).
* The spike rule uses a median baseline; if errors dominate the logs, real spikes can be missed.
* Text-based status detection needs explicit cues (`status=`, `HTTP 502`); a status buried in free prose is missed.
* No semantic understanding: two different problems that print the same message look identical.

**Grouping and severity**
* Incidents are per service and time-based. "Possibly related" links across services show **overlap in time,
  not causation**. One outage can therefore appear as several incidents.
* Severity is triage guidance. It knows nothing about business impact except via `critical_services`.
  It is not an alerting policy; page on SLO burn-rate alerts instead.

**Input**
* Naive timestamps are assumed to be UTC. Numeric log levels are deliberately unsupported (ambiguous).
* Whole files are re-read each run (no tailing, no offsets). `serve` is fine for demos and modest logs;
  for large volumes use `--metrics-file` from a scheduled job or a real log pipeline.
* CloudWatch: capped by `--max-events`; the AWS path is unit-tested against a fake client and has **not** been
  validated against a live AWS account in this repository's development environment.

**AI layer**
* Output is generated text. Validation checks structure, citations and obviously state-changing steps; it
  cannot check that a *sentence is true*. Redaction is regex-based best effort and can miss secrets or names.
* The offline provider is templates, not intelligence.
* Provider behaviour (rate limits, model names, pricing) changes; verify against current provider docs.

**Operations**
* The Docker image and the Prometheus/Grafana compose demo are provided as examples; the compose stack was not
  exercised end-to-end in the environment this code was written in.
