"""Command executor, interactive runner, clipboard integration, and history."""

import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

from shx.core.config import DEFAULT_CONFIG_DIR

DEFAULT_HISTORY_FILE = DEFAULT_CONFIG_DIR / "history.log"


def get_history_file() -> Path:
    """Return configured history file path, supporting test environment override."""
    env_override = os.environ.get("SHX_HISTORY_FILE")
    if env_override:
        return Path(env_override)
    return DEFAULT_HISTORY_FILE


def copy_to_clipboard(text: str) -> bool:
    """Copy given text to system clipboard across macOS, Linux, and Windows."""
    system = platform.system()
    try:
        if system == "Darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        elif system == "Linux":
            for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, close_fds=True)
                    p.communicate(input=text.encode("utf-8"))
                    if p.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
        elif system == "Windows":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
    except Exception:
        pass
    return False


def log_command_history(command: str, exit_code: Optional[int] = None, output_snippet: str = "") -> None:
    """Append command and result to shx history log using JSONL format with 0600 permissions."""
    try:
        hfile = get_history_file()
        hfile.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            try:
                os.chmod(hfile.parent, 0o700)
            except OSError:
                pass

        entry = {
            "ts": datetime.now().isoformat(),
            "cmd": command,
            "exit": exit_code,
            "out": output_snippet.strip().replace("\n", " ")[:300] if output_snippet else "",
        }
        line = json.dumps(entry) + "\n"

        fd = os.open(hfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with open(fd, "a", encoding="utf-8") as f:
            f.write(line)

        if os.name == "posix":
            try:
                os.chmod(hfile, 0o600)
            except OSError:
                pass
    except Exception:
        pass


def get_last_history_command() -> Optional[str]:
    """Retrieve the most recent command recorded in shx history, supporting JSONL and legacy formats."""
    hfile = get_history_file()
    if not hfile.exists():
        return None
    try:
        lines = hfile.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    data = json.loads(line_str)
                    if "cmd" in data:
                        return data["cmd"]
                except Exception:
                    pass
            if "] CMD: " in line_str:
                return line_str.split("] CMD: ", 1)[1].strip()
    except Exception:
        pass
    return None


def execute_command_interactive(command: str) -> int:
    """Execute shell command with full interactive terminal passthrough, handling Ctrl+C cleanly."""
    shell = os.environ.get("SHELL", "/bin/zsh" if platform.system() == "Darwin" else "/bin/bash")
    try:
        proc = subprocess.run([shell, "-c", command])
        exit_code = proc.returncode
        log_command_history(command, exit_code=exit_code)
        return exit_code
    except KeyboardInterrupt:
        log_command_history(command, exit_code=130, output_snippet="KeyboardInterrupt (SIGINT)")
        return 130
    except Exception as e:
        print(f"\nExecution error: {e}", file=sys.stderr)
        log_command_history(command, exit_code=1, output_snippet=str(e))
        return 1


SHELL_STATE_COMMANDS = {
    "cd",
    "pushd",
    "popd",
    "source",
    ".",
    "export",
    "unset",
    "alias",
    "unalias",
}


def is_shell_state_command(command: str) -> bool:
    """Check if a shell command alters the parent shell's working directory or environment."""
    import shlex

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        tokens = list(lexer)
    except Exception:
        tokens = command.split()

    delimiters = {";", "&&", "||", "|", "&", "\n"}
    expect_command = True

    for token in tokens:
        if expect_command:
            # Skip environment assignments before the command name (e.g. VAR=1 cd ...)
            if "=" in token and not token.startswith("="):
                continue
            # Strip path and leading backslash (e.g. /usr/bin/cd or \cd)
            raw_token = token.lstrip("\\")
            cmd_name = Path(raw_token).name or raw_token
            if cmd_name in SHELL_STATE_COMMANDS:
                return True
            expect_command = False
        elif token in delimiters:
            expect_command = True

    return False


def get_shell_init_script(shell_name: str) -> str:
    """Return the shell function wrapper that enables directory navigation and environment changes."""
    s = shell_name.strip().lower()
    if s == "zsh":
        return """# shx shell integration for zsh
shx() {
    local tmp
    tmp="$(mktemp -t shx_cmd.XXXXXX)"
    SHX_CMD_FILE="$tmp" command shx "$@"
    local ret=$?
    if [[ -f "$tmp" ]]; then
        local cmd
        cmd="$(cat "$tmp")"
        rm -f "$tmp"
        if [[ -n "$cmd" ]]; then
            print -s "$cmd" 2>/dev/null || true
            eval "$cmd"
            ret=$?
        fi
    fi
    return $ret
}
"""
    elif s == "bash":
        return """# shx shell integration for bash
shx() {
    local tmp
    tmp="$(mktemp -t shx_cmd.XXXXXX)"
    SHX_CMD_FILE="$tmp" command shx "$@"
    local ret=$?
    if [ -f "$tmp" ]; then
        local cmd
        cmd="$(cat "$tmp")"
        rm -f "$tmp"
        if [ -n "$cmd" ]; then
            history -s "$cmd" 2>/dev/null || true
            eval "$cmd"
            ret=$?
        fi
    fi
    return $ret
}
"""
    elif s == "fish":
        return """# shx shell integration for fish
function shx
    set -l tmp (mktemp -t shx_cmd.XXXXXX)
    env SHX_CMD_FILE="$tmp" command shx $argv
    set -l ret $status
    if test -f "$tmp"
        set -l cmd (cat "$tmp")
        rm -f "$tmp"
        if test -n "$cmd"
            history add "$cmd"
            eval "$cmd"
            set ret $status
        end
    end
    return $ret
end
"""
    else:
        return """# shx shell integration
shx() {
    local tmp
    tmp="$(mktemp -t shx_cmd.XXXXXX)"
    SHX_CMD_FILE="$tmp" command shx "$@"
    local ret=$?
    if [ -f "$tmp" ]; then
        local cmd
        cmd="$(cat "$tmp")"
        rm -f "$tmp"
        if [ -n "$cmd" ]; then
            eval "$cmd"
            ret=$?
        fi
    fi
    return $ret
}
"""


def install_shell_integration(shell_name: Optional[str] = None) -> Tuple[bool, str]:
    """Append shell integration line to the appropriate user shell rc file."""
    if not shell_name:
        shell_env = os.environ.get("SHELL", "")
        shell_name = Path(shell_env).name if shell_env else ("zsh" if platform.system() == "Darwin" else "bash")
    shell_clean = shell_name.strip().lower()

    home = Path.home()
    if shell_clean == "zsh":
        rc_path = home / ".zshrc"
    elif shell_clean == "bash":
        if platform.system() == "Darwin":
            rc_path = home / ".bash_profile" if (home / ".bash_profile").exists() else home / ".bashrc"
        else:
            rc_path = home / ".bashrc"
    elif shell_clean == "fish":
        rc_path = home / ".config" / "fish" / "config.fish"
    else:
        rc_path = home / ".profile"

    init_cmd = f'eval "$(shx init {shell_clean})"'
    if shell_clean == "fish":
        init_cmd = "shx init fish | source"

    try:
        content = ""
        if rc_path.exists():
            content = rc_path.read_text(encoding="utf-8")

        if "shx init" in content:
            return True, f"Shell integration is already installed in {rc_path}"

        rc_path.parent.mkdir(parents=True, exist_ok=True)
        with open(rc_path, "a", encoding="utf-8") as f:
            f.write(f"\n# shx shell integration (enables directory navigation & environment persistence)\n{init_cmd}\n")

        return True, f"Successfully installed shell integration into {rc_path}. Run 'source {rc_path}' to activate."
    except Exception as e:
        return False, f"Could not write to {rc_path}: {e}"

