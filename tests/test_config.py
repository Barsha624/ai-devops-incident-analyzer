import pytest

from incident_analyzer.config import AnalyzerConfig, load_config
from incident_analyzer.exceptions import ConfigError


def write(tmp_path, text):
    path = tmp_path / "cfg.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_are_valid_and_ai_is_off():
    config = load_config(None)
    assert config.ai.enabled is False
    assert config.analysis.gap_seconds == 300
    config.validate()


def test_toml_overrides_defaults(tmp_path):
    path = write(
        tmp_path,
        """
[analysis]
gap_seconds = 120
spike_factor = 4
critical_services = ["payments-worker"]

[logging]
level = "INFO"
format = "json"
""",
    )
    config = load_config(path)
    assert config.analysis.gap_seconds == 120
    assert config.analysis.spike_factor == 4.0
    assert config.analysis.critical_services == ("payments-worker",)
    assert config.logging.format == "json"


def test_unknown_key_is_rejected_with_helpful_message(tmp_path):
    path = write(tmp_path, "[analysis]\ngap_second = 10\n")
    with pytest.raises(ConfigError, match=r"unknown option 'gap_second'.*gap_seconds"):
        load_config(path)


def test_unknown_section_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown section"):
        load_config(write(tmp_path, "[mystery]\nx = 1\n"))


@pytest.mark.parametrize(
    "body",
    [
        "[analysis]\ngap_seconds = 'ten'",
        "[analysis]\ngap_seconds = true",
        "[analysis]\nspike_factor = 'big'",
        "[analysis]\ncritical_services = 'payments'",
        "[ai]\nenabled = 'yes'",
        "[logging]\nlevel = 5",
    ],
)
def test_wrong_types_are_rejected(tmp_path, body):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, body))


@pytest.mark.parametrize(
    "body",
    [
        "[analysis]\ngap_seconds = 0",
        "[analysis]\nmin_events = 0",
        "[analysis]\nspike_factor = 1.0",
        "[logging]\nlevel = 'LOUD'",
        "[logging]\nformat = 'xml'",
        "[ai]\nprovider = 'magic'",
        "[ai]\nmax_retries = -1",
    ],
)
def test_out_of_range_values_are_rejected(tmp_path, body):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, body))


def test_invalid_toml_syntax(tmp_path):
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(write(tmp_path, "this is = = not toml"))


def test_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/no/such/config.toml")


def test_analysis_settings_are_json_friendly():
    import json

    json.dumps(AnalyzerConfig().analysis_settings())


def test_example_config_in_repo_is_valid():
    from pathlib import Path

    example = Path(__file__).resolve().parent.parent / "config" / "analyzer.example.toml"
    if example.exists():
        load_config(example)
