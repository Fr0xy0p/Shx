"""Unit tests for shx CLI, Typer commands, and rich UI interactions."""

import io
from typer.testing import CliRunner
from rich.console import Console

import shx
from shx.cli import app
from shx.core.safety.rules import RiskReport, RiskLevel
from shx.ui.console import prompt_action, render_safety_report
from shx.llm.client import LLMClient

runner = CliRunner()


def test_cli_version():
    res1 = runner.invoke(app, ["--version"])
    assert res1.exit_code == 0
    assert f"shx version {shx.__version__}" in res1.stdout

    res2 = runner.invoke(app, ["-V"])
    assert res2.exit_code == 0
    assert f"shx version {shx.__version__}" in res2.stdout


def test_cli_help_flags():
    res1 = runner.invoke(app, ["-h"])
    assert res1.exit_code == 0
    assert "Usage:" in res1.stdout

    res2 = runner.invoke(app, ["--help"])
    assert res2.exit_code == 0
    assert "Usage:" in res2.stdout


def test_unquoted_check_and_explain():
    res_check = runner.invoke(app, ["check", "rm", "-rf", "/"])
    assert res_check.exit_code == 0
    assert "CRITICAL" in res_check.stdout

    res_explain = runner.invoke(app, ["explain", "tar", "-xzvf", "a.tgz"])
    # Offline table should be rendered even without active LLM call
    assert "Extract" in res_explain.stdout or res_explain.exit_code == 0


def test_config_invalid_provider_no_wizard():
    res = runner.invoke(app, ["config", "--provider", "invalid_provider"])
    assert res.exit_code != 0
    assert "Unsupported provider" in res.stdout
    assert "shx Interactive Setup" not in res.stdout


def test_config_reject_anthropic():
    res = runner.invoke(app, ["config", "--provider", "anthropic"])
    assert res.exit_code != 0
    assert "Unsupported provider" in res.stdout


def test_config_invalid_key_format():
    res = runner.invoke(app, ["config", "--set-key", "invalid_key_format"])
    assert res.exit_code != 0
    assert "Invalid format" in res.stdout
    assert "shx Interactive Setup" not in res.stdout


def test_config_flags_roundtrip(tmp_path, monkeypatch):
    test_cfg = tmp_path / "cfg.json"
    monkeypatch.setenv("SHX_CONFIG_PATH", str(test_cfg))

    r1 = runner.invoke(app, ["config", "--no-confirm", "--no-strict-safety", "--auto-copy"])
    assert r1.exit_code == 0

    r2 = runner.invoke(app, ["config", "--show"])
    assert r2.exit_code == 0
    assert "Require Confirmation" in r2.stdout
    assert "False" in r2.stdout
    assert "Strict Safety" in r2.stdout
    assert "Auto-copy Clipboard" in r2.stdout


def test_prompt_action_defaults(monkeypatch):
    import importlib
    console_module = importlib.import_module("shx.ui.console")

    # Empty input on SAFE report returns 'e' (Execute)
    safe_rep = RiskReport(command="ls", level=RiskLevel.SAFE)
    monkeypatch.setattr(console_module.console, "input", lambda prompt: "")
    assert prompt_action(safe_rep) == "e"

    # Empty input on DANGEROUS report returns 'a' (Abort)
    dang_rep = RiskReport(command="rm -r ./build", level=RiskLevel.DANGEROUS)
    assert prompt_action(dang_rep) == "a"

    # Empty input on CRITICAL/BLOCKED report returns 'a' (Abort)
    crit_rep = RiskReport(command="rm -rf /", level=RiskLevel.CRITICAL, is_blocked=True)
    assert prompt_action(crit_rep) == "a"


def test_markup_injection_escaping(monkeypatch):
    buf = io.StringIO()
    test_console = Console(file=buf, record=True)
    import importlib
    console_module = importlib.import_module("shx.ui.console")
    monkeypatch.setattr(console_module, "console", test_console)

    rep = RiskReport(command="ls [a-z]*.txt [/tmp]", level=RiskLevel.SAFE)
    render_safety_report(rep)
    out = buf.getvalue()
    assert "[a-z]*.txt" in out
    assert "[/tmp]" in out


def test_explain_llm_failure(monkeypatch):
    def fake_explain(*args, **kwargs):
        raise ValueError("Network timeout")

    monkeypatch.setattr(LLMClient, "explain", fake_explain)

    # When explaining error text, skip flags and fail on LLM error
    res_err = runner.invoke(app, ["explain", "--error", "segmentation fault (core dumped)"])
    assert res_err.exit_code != 0
    assert "Error explaining target" in res_err.stdout

    # When explaining command with local flags, show local table and warning
    res_local = runner.invoke(app, ["explain", "tar -xzvf a.tgz"])
    assert "Warning: AI explanation unavailable" in res_local.stdout
