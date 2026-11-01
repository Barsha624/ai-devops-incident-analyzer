# Project walkthrough (the order to learn it in)

Read the code in the same order the project was built. Each stage is small enough to understand fully and to
retype from memory. The first commits follow the same stages (parsing, detection, then grouping/severity/report/CLI).

| Stage | Read | What you should be able to explain | Try it |
|---|---|---|---|
| 1. Parse | `models.py`, `timestamps.py`, `json_parser.py`, `text_parser.py`, `reader.py` | One bad line never aborts the run; why `parse_lines` is a generator; how a stack trace is attached to its log line | `incident-analyzer analyze samples/inventory-service.log --format json \| jq .inputs` |
| 2. Detect | `detection.py`, `signatures.py`, `spikes.py` | Each rule id, its exclusions, why a median baseline | Add a line with `HTTP 502` and see the finding change |
| 3. Group + score | `incidents.py`, `severity.py` | Gap-based clustering, why "related" is not "caused by", every severity point has a reason | Change `--gap-seconds` and watch incidents split/merge |
| 4. Report | `report.py` | The JSON dict is the source of truth; the terminal view renders from it | `--format both -o out.json` |
| 5. Quality | `tests/`, `config.py`, `exceptions.py`, `logging_setup.py` | Test names read as requirements; unknown config keys are errors; exit codes | `make check` |
| 6. Ship | `Dockerfile`, `.github/workflows/ci.yml` | Multi-stage build, non-root user, what each CI job proves | `docker build -t x . && docker run --rm x analyze /opt/samples` |
| 7. Observe | `metrics.py`, `monitoring/` | Gauges vs counters, textfile collector vs exporter, atomic writes | `serve samples --port 9108` then `curl :9108/metrics` |
| 8. AI | `ai/`, `redaction.py` | The trust boundary: what is sent, what is validated, what can never change | `--ai-dry-run`, then `--ai --ai-provider offline` |
| 9. AWS | `cloudwatch.py` | Injectable client, pagination, actionable error messages, least-privilege IAM | read the tests; run only with your own AWS account |

## The two-minute explanation (for an interview)

"It reads JSON or text logs, normalises them into events, and applies documented rules for 5xx, timeouts,
repeated exceptions and error spikes. Findings are clustered into incidents per service and scored with an additive
rule table where every point has a written reason, so you can always answer why something is HIGH. Output is a
JSON report plus a terminal summary, with the exact log lines as evidence. The core has zero dependencies and no
network. On top there is an optional AI explanation: it only sees a small redacted slice of the verified
evidence, must separate cited facts from hypotheses, can't change severity, and nothing it suggests is executed.
I also built an evaluation command, because without labelled data I can't honestly claim any accuracy."

## Exercises without AI help

See the end of [interview-guide.md](interview-guide.md).
