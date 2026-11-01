# Monitoring: Prometheus and Grafana (optional)

You do not need any of this to use the analyzer. It exists so the tool's findings can show up on a dashboard
and in alert rules next to your other metrics.

## Two ways to expose metrics

**1. A file, once per run** (cron job, CI step, or node_exporter's *textfile collector*):

```bash
incident-analyzer analyze /var/log/myapp --metrics-file /var/lib/node_exporter/textfile/incidents.prom
```

The file is written atomically (temp file + rename) so a scraper never reads half a file.

**2. A small HTTP exporter** that re-analyses the logs every N seconds:

```bash
incident-analyzer serve /var/log/myapp --port 9108 --interval 30
curl -s localhost:9108/metrics | head
curl -s localhost:9108/healthz
```

`serve` fails fast on a bad path (exit code 2) instead of starting a "healthy" exporter that reports nothing.
If a *later* refresh fails (file rotated away, permissions), it keeps serving the last good numbers and
increments `incident_analyzer_analysis_failures_total`.

## Metrics

All are **gauges describing the latest analysis snapshot** (the whole input is re-read each time; there is no
tailing), except the one true counter.

| Metric | Labels | Meaning |
|---|---|---|
| `incident_analyzer_incidents` | `severity` | incidents by severity (all four always exported, zeros included) |
| `incident_analyzer_findings` | `kind` | findings by detection kind |
| `incident_analyzer_highest_severity` | | 0 none, 1 low, 2 medium, 3 high, 4 critical |
| `incident_analyzer_error_spikes` | | spike periods detected |
| `incident_analyzer_events_parsed` | | events parsed |
| `incident_analyzer_malformed_lines` | | lines not understood |
| `incident_analyzer_analysis_duration_seconds` | | duration of the last analysis |
| `incident_analyzer_last_analysis_timestamp_seconds` | | Unix time of the last success (use it to detect staleness) |
| `incident_analyzer_analysis_failures_total` | | counter of failed refreshes |
| `incident_analyzer_info` | `version` | build info, always 1 |

Label values are **bounded** (4 severities, 4 kinds). Never put service names, ids or messages in labels
here: unbounded labels cause cardinality explosions in Prometheus.

## Local demo stack

`monitoring/` contains a Compose file, Prometheus config, example alert rules and a Grafana dashboard. They are
**examples to start from**, not a hardened production setup.

```bash
cd monitoring
export GRAFANA_ADMIN_PASSWORD='pick-a-password'   # required: there is no default on purpose
docker compose up --build
```

* Exporter: <http://127.0.0.1:9108/metrics> (analyses the synthetic `samples/`)
* Prometheus: <http://127.0.0.1:9090> (Status > Targets should show `incident-analyzer` UP; Alerts tab shows rules)
* Grafana: <http://127.0.0.1:3000> (user `admin`, your password; dashboard "Incident Analyzer" is pre-provisioned)

All ports are bound to `127.0.0.1`. To analyse your own logs, change the volume in `docker-compose.yml`
to point at them (read-only).

### Import the dashboard into an existing Grafana

Dashboards > New > Import > upload `monitoring/grafana/dashboards/incident-analyzer.json` and choose your
Prometheus data source (the file assumes a data source with uid `prometheus`; edit it if yours differs).

## Alert rules (examples)

`monitoring/alerts.yml`: critical/high incident present, analyzer stale (> 5 min since last analysis),
analyses failing, and "logs mostly unparseable". Thresholds are illustrative: tune them. Note the
important design point: **alert on symptoms you can act on, not on every finding**. A finding count is a
diagnostic signal; user-facing SLO burn rate is what should page someone.

## Honest caveats

* Snapshot gauges mean `rate()` and `increase()` on them are not meaningful (except on the failures counter).
* Re-reading whole files every interval is fine for demos and modest logs; for large logs use `--metrics-file`
  from a periodic job, or add a tailing mode (see [roadmap](roadmap.md)).
* This is not a replacement for a log pipeline (Loki, CloudWatch Logs Insights, Elasticsearch). It is a
  deterministic *analysis* layer you can run over their exports.

## Kubernetes (not required)

The exporter is a single stateless container with `/healthz`, so it maps directly onto a Deployment with a
`ConfigMap` for the TOML file, a read-only volume or sidecar for logs, and a `ServiceMonitor` or scrape
annotation. That is intentionally left out of the first version: containerise first, orchestrate later.
