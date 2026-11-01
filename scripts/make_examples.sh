#!/bin/sh
set -eu
mkdir -p examples
A="python -m incident_analyzer"

$A analyze samples --no-color > examples/terminal-summary.txt
$A analyze samples --format json -o examples/report.json
$A analyze samples --metrics-file examples/metrics.prom > /dev/null
$A analyze samples --ai --ai-provider offline --format json -o examples/report-with-offline-ai.json
$A analyze samples --ai-dry-run --ai-provider anthropic --format json -o examples/ai-dry-run.json
echo "examples written to examples/"
