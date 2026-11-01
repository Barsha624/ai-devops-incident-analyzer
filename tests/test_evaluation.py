import json
from pathlib import Path

import pytest

from helpers import at
from incident_analyzer.cli import main
from incident_analyzer.evaluation import evaluate, load_labels, render
from incident_analyzer.exceptions import ConfigError

ROOT = Path(__file__).resolve().parent.parent


def iso(seconds):
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_dataset(tmp_path, expected):
    lines = [f"{iso(s)} ERROR [api] upstream returned HTTP 502 for GET /x" for s in range(0, 40, 4)]
    (tmp_path / "api.log").write_text("\n".join(lines) + "\n")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"logs": ["api.log"], "expected_incidents": expected}))
    return labels


def window(service, start, end):
    return {"service": service, "start": iso(start), "end": iso(end)}


def test_perfect_match(tmp_path):
    result = evaluate(make_dataset(tmp_path, [window("api", 0, 40)]))
    assert (result.recall, result.precision) == (1.0, 1.0)


def test_missed_incident_lowers_recall(tmp_path):
    result = evaluate(make_dataset(tmp_path, [window("api", 0, 40), window("db", 0, 40)]))
    assert result.recall == 0.5 and result.precision == 1.0 and result.missed == ["db"]


def test_unexpected_incident_lowers_precision(tmp_path):
    result = evaluate(make_dataset(tmp_path, [window("api", 500, 600)]))  # wrong time
    assert result.precision == 0.0 and result.recall == 0.0 and len(result.unexpected) == 1


def test_no_expected_and_no_detected_gives_undefined_not_a_fake_100_percent(tmp_path):
    (tmp_path / "ok.log").write_text(f"{iso(0)} INFO [api] fine\n")
    labels = tmp_path / "l.json"
    labels.write_text(json.dumps({"logs": ["ok.log"], "expected_incidents": []}))
    result = evaluate(labels)
    assert result.recall is None and result.precision is None
    assert "n/a" in render(result)


@pytest.mark.parametrize(
    "content", ["not json", "{}", '{"logs": [], "expected_incidents": [{"service": "x"}]}']
)
def test_bad_labels_files_raise_config_errors(tmp_path, content):
    path = tmp_path / "l.json"
    path.write_text(content)
    with pytest.raises(ConfigError):
        load_labels(path)


def test_shipped_synthetic_labels_are_a_working_regression_check():
    """Guards the detection rules against regressions on the synthetic sample set.

    This is NOT an accuracy claim: the data and the labels were written together.
    """
    result = evaluate(ROOT / "evaluation" / "synthetic-labels.json")
    assert result.expected == 4
    assert result.missed == [] and result.unexpected == []


def test_cli_evaluate(capsys):
    assert main(["evaluate", str(ROOT / "evaluation" / "synthetic-labels.json")]) == 0
    assert "recall" in capsys.readouterr().out
