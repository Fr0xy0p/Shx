"""Command executor, interactive runner, clipboard integration, and history."""

import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional
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
