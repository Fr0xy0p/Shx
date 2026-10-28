"""Command executor, interactive runner, clipboard integration, and history."""

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

from shx.core.config import DEFAULT_CONFIG_DIR

HISTORY_FILE = DEFAULT_CONFIG_DIR / "history.log"


def copy_to_clipboard(text: str) -> bool:
    """Copy given text to system clipboard across macOS, Linux, and Windows."""
    system = platform.system()
    try:
        if system == "Darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        elif system == "Linux":
            # Try wl-copy first (Wayland), then xclip, then xsel
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
    """Append command and result to shx history log."""
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().isoformat()
            f.write(f"[{timestamp}] CMD: {command}\n")
            if exit_code is not None:
                f.write(f"[{timestamp}] EXIT: {exit_code}\n")
            if output_snippet:
                clean_snippet = output_snippet.strip().replace("\n", " ")[:300]
                f.write(f"[{timestamp}] OUT: {clean_snippet}\n")
            f.write("---\n")
    except Exception:
        pass


def get_last_history_command() -> Optional[str]:
    """Retrieve the most recent command recorded in shx history."""
    if not HISTORY_FILE.exists():
        return None
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if "] CMD: " in line:
                return line.split("] CMD: ", 1)[1].strip()
    except Exception:
        pass
    return None


def execute_command_interactive(command: str) -> int:
    """Execute shell command with full interactive terminal passthrough."""
    shell = os.environ.get("SHELL", "/bin/zsh" if platform.system() == "Darwin" else "/bin/bash")
    try:
        # Run command directly in user shell
        proc = subprocess.run([shell, "-c", command])
        exit_code = proc.returncode
        log_command_history(command, exit_code=exit_code)
        return exit_code
    except Exception as e:
        print(f"\nExecution error: {e}", file=sys.stderr)
        log_command_history(command, exit_code=1, output_snippet=str(e))
        return 1
