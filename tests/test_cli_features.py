import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from helpers import at
from incident_analyzer import cli
from incident_analyzer.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def iso(seconds: int) -> str:
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def leaky_log(tmp_path: Path) -> Path:
    path = tmp_path / "pay.log"
    lines = [
        f"{iso(s)} ERROR [pay] charge failed for bob@example.com password=hunter2hunter2 "
        f"from 203.0.113.7 upstream returned HTTP 502 for POST /pay"
        for s in range(0, 40, 4)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_json(
    *argv: str,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    code = main(["analyze", *argv, "--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def test_ai_is_off_by_default(leaky_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, report = run_json(str(leaky_log), capsys=capsys)
    assert report["ai"] is None


def test_core_run_never_imports_ai_or_optional_modules() -> None:
    code = (
        "import sys\n"
        "from incident_analyzer.cli import main\n"
        "main(['analyze', 'samples/healthy-service.log', '--format', 'json', '-o', "
        "'/dev/null'])\n"
        "loaded = [m for m in ('incident_analyzer.ai', 'incident_analyzer.metrics', "
        "'incident_analyzer.cloudwatch', 'boto3') if m in sys.modules]\n"
        "assert not loaded, loaded\n"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

    subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        check=True,
        timeout=60,
    )


def test_offline_ai_adds_a_separate_section_and_keeps_severity(
    leaky_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, plain = run_json(str(leaky_log), capsys=capsys)
    _, with_ai = run_json(
        str(leaky_log),
        "--ai",
        "--ai-provider",
        "offline",
        capsys=capsys,
    )

    assert with_ai["ai"]["status"] == "ok"
    assert with_ai["incidents"] == plain["incidents"]
    assert with_ai["summary"] == plain["summary"]


def test_dry_run_prints_a_redacted_request_and_sends_nothing(
    leaky_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, report = run_json(
        str(leaky_log),
        "--ai-dry-run",
        "--ai-provider",
        "anthropic",
        capsys=capsys,
    )

    ai = report["ai"]
    assert ai["status"] == "dry_run" and ai["would_send_externally"] is True

    request = ai["request"]["user"]
    assert "hunter2hunter2" not in request
    assert "bob@example.com" not in request
    assert "203.0.113.7" not in request


def test_external_provider_is_blocked_without_consent_but_analysis_still_succeeds(
    leaky_log: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    code, report = run_json(
        str(leaky_log),
        "--ai",
        "--ai-provider",
        "anthropic",
        capsys=capsys,
    )

    assert code == 0 and report["ai"]["status"] == "blocked"
    assert report["summary"]["incidents"] == 1


def test_kill_switch_environment_variable(
    leaky_log: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INCIDENT_ANALYZER_DISABLE_AI", "1")

    _, report = run_json(
        str(leaky_log),
        "--ai",
        "--ai-provider",
        "offline",
        capsys=capsys,
    )

    assert report["ai"]["status"] == "disabled"


def test_ai_can_be_enabled_from_config_file_and_terminal_shows_section(
    leaky_log: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "c.toml"
    config.write_text(
        '[ai]\nenabled = true\nprovider = "offline"\n',
        encoding="utf-8",
    )

    assert main(["analyze", str(leaky_log), "--config", str(config), "--no-color"]) == 0

    out = capsys.readouterr().out
    assert "AI explanation (generated text; unverified; does not change severity)" in out
    assert "observed [INC-001" in out


def test_redact_flag_cleans_report_excerpts(
    leaky_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, raw = run_json(str(leaky_log), capsys=capsys)
    _, clean = run_json(str(leaky_log), "--redact", capsys=capsys)

    assert "hunter2hunter2" in json.dumps(raw)  # proves the flag is what removes it
    assert "hunter2hunter2" not in json.dumps(clean)
    assert "bob@example.com" not in json.dumps(clean)


def test_metrics_file_is_written(
    leaky_log: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "m" / "out.prom"

    assert main(
        ["analyze", str(leaky_log), "--metrics-file", str(target), "--no-color"]
    ) == 0

    text = target.read_text(encoding="utf-8")
    assert 'incident_analyzer_incidents{severity="' in text
    assert "incident_analyzer_events_parsed 10" in text


def test_analyze_needs_a_source(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze"]) == 2
    assert "--cloudwatch-group" in capsys.readouterr().err


def test_cloudwatch_source_is_wired_in(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from incident_analyzer.analyzer import lines_source

    lines = [
        f"{iso(s)} ERROR [cw] upstream returned HTTP 503 for GET /x"
        for s in range(0, 40, 4)
    ]

    seen: dict[str, str] = {}

    def fake_source(args: Any) -> tuple[Any, list[str]]:
        seen["group"], seen["since"] = args.cloudwatch_group, args.since
        return (
            lines_source(lines, "cloudwatch:/aws/x", "cw"),
            ["fetch was truncated"],
        )

    monkeypatch.setattr(cli, "_cloudwatch_source", fake_source)

    code, report = run_json(
        "--cloudwatch-group",
        "/aws/x",
        "--since",
        "2h",
        capsys=capsys,
    )

    assert code == 0 and seen == {"group": "/aws/x", "since": "2h"}
    assert report["summary"]["incidents"] == 1
    assert "fetch was truncated" in report["warnings"]


@pytest.mark.parametrize(
    "argv",
    [
        ["serve", str(SAMPLES), "--interval", "0"],
        ["serve", str(SAMPLES), "--port", "70000"],
        ["serve", "/definitely/not/here"],
    ],
)
def test_serve_rejects_bad_input_before_listening(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(argv) == 2
    assert "error:" in capsys.readouterr().err