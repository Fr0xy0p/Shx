"""Unit tests for executor, history logging, and Ctrl+C interrupt handling."""

import os
import stat
import subprocess
from shx.core.executor import (
    log_command_history,
    get_last_history_command,
    execute_command_interactive,
    is_shell_state_command,
    get_shell_init_script,
    install_shell_integration,
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


def test_is_shell_state_command():
    assert is_shell_state_command("cd ~/CodeForces") is True
    assert is_shell_state_command("cd ..") is True
    assert is_shell_state_command("cd") is True
    assert is_shell_state_command("mkdir foo && cd foo") is True
    assert is_shell_state_command("FOO=1 cd /tmp") is True
    assert is_shell_state_command("pushd /tmp") is True
    assert is_shell_state_command("popd") is True
    assert is_shell_state_command("source .venv/bin/activate") is True
    assert is_shell_state_command(". ~/.bashrc") is True
    assert is_shell_state_command("export MY_VAR=1") is True
    assert is_shell_state_command("unset MY_VAR") is True
    assert is_shell_state_command("alias ll='ls -la'") is True
    assert is_shell_state_command("unalias ll") is True

    assert is_shell_state_command("ls -la") is False
    assert is_shell_state_command("git status") is False
    assert is_shell_state_command("echo 'cd is cool'") is False
    assert is_shell_state_command("cat README.md | grep cd") is False


def test_get_shell_init_script():
    zsh_script = get_shell_init_script("zsh")
    assert "shx()" in zsh_script
    assert "SHX_CMD_FILE" in zsh_script
    assert 'eval "$cmd"' in zsh_script

    bash_script = get_shell_init_script("bash")
    assert "shx()" in bash_script
    assert "history -s" in bash_script

    fish_script = get_shell_init_script("fish")
    assert "function shx" in fish_script
    assert 'eval "$cmd"' in fish_script


def test_install_shell_integration(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    success, msg = install_shell_integration("zsh")
    assert success is True
    zshrc = tmp_path / ".zshrc"
    assert zshrc.exists()
    content = zshrc.read_text(encoding="utf-8")
    assert 'eval "$(shx init zsh)"' in content

    # Second install should detect already installed
    success2, msg2 = install_shell_integration("zsh")
    assert success2 is True
    assert "already installed" in msg2


