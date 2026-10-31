import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import at
from incident_analyzer.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def iso(seconds):
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def bad_log(tmp_path):
    path = tmp_path / "api.log"
    lines = [f"{iso(s)} ERROR [api] upstream returned HTTP 502 for GET /x" for s in range(0, 40, 4)]
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.fixture
def good_log(tmp_path):
    path = tmp_path / "ok.log"
    path.write_text("\n".join(f"{iso(s)} INFO [api] fine" for s in range(0, 40, 4)) + "\n")
    return path


def test_terminal_output_default(bad_log, capsys):
    assert main(["analyze", str(bad_log), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "INC-001" in out and "api" in out


def test_json_to_stdout_is_valid_json(bad_log, capsys):
    assert main(["analyze", str(bad_log), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["incidents"] == 1


def test_json_to_file(bad_log, tmp_path, capsys):
    target = tmp_path / "out" / "r.json"
    assert main(["analyze", str(bad_log), "--format", "json", "-o", str(target)]) == 0
    assert json.loads(target.read_text())["summary"]["incidents"] == 1
    assert capsys.readouterr().out == ""  # stdout stays clean when writing to a file


def test_both_requires_output(bad_log, capsys):
    assert main(["analyze", str(bad_log), "--format", "both"]) == 2
    assert "--output" in capsys.readouterr().err


def test_both_writes_file_and_prints_summary(bad_log, tmp_path, capsys):
    target = tmp_path / "r.json"
    assert main(["analyze", str(bad_log), "--format", "both", "-o", str(target), "--no-color"]) == 0
    assert "INC-001" in capsys.readouterr().out
    assert target.exists()


class TestFailOn:
    def test_exit_1_when_threshold_reached(self, bad_log, tmp_path):
        assert (
            main(
                [
                    "analyze",
                    str(bad_log),
                    "--fail-on",
                    "medium",
                    "--format",
                    "json",
                    "-o",
                    str(tmp_path / "r.json"),
                ]
            )
            == 1
        )

    def test_exit_0_when_below_threshold(self, bad_log, tmp_path):
        assert (
            main(
                [
                    "analyze",
                    str(bad_log),
                    "--fail-on",
                    "critical",
                    "--format",
                    "json",
                    "-o",
                    str(tmp_path / "r.json"),
                ]
            )
            == 0
        )

    def test_exit_0_for_healthy_logs(self, good_log, capsys):
        assert main(["analyze", str(good_log), "--fail-on", "low"]) == 0


class TestErrors:
    def test_missing_file_exit_2(self, capsys):
        assert main(["analyze", "/no/such/file.log"]) == 2
        assert "does not exist" in capsys.readouterr().err

    def test_invalid_option_value_exit_2(self, bad_log, capsys):
        assert main(["analyze", str(bad_log), "--gap-seconds", "0"]) == 2
        assert "gap_seconds" in capsys.readouterr().err

    def test_bad_config_file_exit_2(self, bad_log, tmp_path, capsys):
        cfg = tmp_path / "bad.toml"
        cfg.write_text("[analysis]\nnope = 1\n")
        assert main(["analyze", str(bad_log), "--config", str(cfg)]) == 2
        assert "unknown option" in capsys.readouterr().err

    def test_strict_mode_exit_2(self, tmp_path, capsys):
        path = tmp_path / "x.log"
        path.write_text(f"{iso(0)} ERROR [a] x\ngarbage\n")
        assert main(["analyze", str(path), "--strict"]) == 2
        assert "strict mode" in capsys.readouterr().err

    def test_empty_directory_exit_2(self, tmp_path, capsys):
        assert main(["analyze", str(tmp_path)]) == 2
        assert "no log files" in capsys.readouterr().err

    def test_json_log_format_for_errors(self, capsys):
        assert main(["analyze", "/no/such.log", "--log-format", "json"]) == 2
        err = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert err["event"] == "command_failed"

    def test_unwritable_output_exit_2(self, bad_log, tmp_path, capsys):
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        assert (
            main(["analyze", str(bad_log), "--format", "json", "-o", str(blocker / "r.json")]) == 2
        )


def test_directory_input_and_stdin(bad_log, monkeypatch, capsys):
    assert main(["analyze", str(bad_log.parent), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["incidents"] == 1

    monkeypatch.setattr(sys, "stdin", io.StringIO(bad_log.read_text()))
    assert main(["analyze", "-", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["inputs"][0]["source"] == "<stdin>"
    assert report["incidents"][0]["service"] == "api"


def test_tuning_flag_changes_result(bad_log, capsys):
    main(["analyze", str(bad_log), "--format", "json", "--min-events", "100"])
    assert json.loads(capsys.readouterr().out)["summary"]["incidents"] == 0


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_python_dash_m_entry_point(bad_log):
    proc = subprocess.run(
        [sys.executable, "-m", "incident_analyzer", "analyze", str(bad_log), "--no-color"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "INC-001" in proc.stdout


class TestSampleData:
    """Regression tests on the committed synthetic samples (structure, not 'accuracy')."""

    def test_samples_produce_the_scripted_incidents(self, capsys):
        assert main(["analyze", str(SAMPLES), "--format", "json"]) == 0
        report = json.loads(capsys.readouterr().out)
        by_service = {i["service"]: i for i in report["incidents"]}
        assert set(by_service) == {
            "payments-worker",
            "checkout-api",
            "web-frontend",
            "inventory-service",
        }
        assert report["summary"]["malformed_lines"] == 3
        assert "reports-service" not in by_service  # the healthy log stays quiet
        assert by_service["inventory-service"]["kinds"] == {"exception": 5}
        assert by_service["payments-worker"]["severity_reasons"]
        assert report["summary"]["below_threshold"]["findings"] == 1

    def test_generator_is_deterministic(self, tmp_path):
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_samples.py"), str(tmp_path)],
            check=True,
            capture_output=True,
        )
        for committed in SAMPLES.glob("*"):
            if committed.suffix in {".log", ".jsonl"}:
                assert (tmp_path / committed.name).read_bytes() == committed.read_bytes(), (
                    committed.name
                )
