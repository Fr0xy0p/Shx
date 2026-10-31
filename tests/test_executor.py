"""Unit tests for executor, history logging, and Ctrl+C interrupt handling."""

import os
import stat
import subprocess
from shx.core.executor import (
    log_command_history,
    get_last_history_command,
    execute_command_interactive,
)


def test_multiline_history_jsonl(tmp_path, monkeypatch):
    hfile = tmp_path / "test_history.log"
    monkeypatch.setenv("SHX_HISTORY_FILE", str(hfile))

    multiline_cmd = "cat << 'EOF' > test.txt\nline 1\nline 2\nEOF"
    log_command_history(multiline_cmd, exit_code=0)

    last = get_last_history_command()
    assert last == multiline_cmd

    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(hfile).st_mode)
        assert mode == 0o600


def test_legacy_history_format(tmp_path, monkeypatch):
    hfile = tmp_path / "test_legacy.log"
    monkeypatch.setenv("SHX_HISTORY_FILE", str(hfile))

    hfile.write_text("[2026-10-31T00:00:00] CMD: echo hello legacy\n[2026-10-31T00:00:00] EXIT: 0\n---\n")
    assert get_last_history_command() == "echo hello legacy"


def test_execute_keyboard_interrupt(monkeypatch, tmp_path):
    hfile = tmp_path / "interrupt_history.log"
    monkeypatch.setenv("SHX_HISTORY_FILE", str(hfile))

    def fake_run(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(subprocess, "run", fake_run)
    code = execute_command_interactive("sleep 100")
    assert code == 130
    assert get_last_history_command() == "sleep 100"
