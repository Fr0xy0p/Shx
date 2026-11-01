"""Terminal and host environment context detection."""

import os
import platform
from pathlib import Path
from typing import Dict, Any


def get_current_shell() -> str:
    """Detect the current active user shell."""
    shell_env = os.environ.get("SHELL", "")
    if shell_env:
        return Path(shell_env).name
    return "zsh" if platform.system() == "Darwin" else "bash"


def get_git_info(cwd: Path) -> Dict[str, Any]:
    """Detect if cwd is inside a git repository, submodule, or worktree."""
    for parent in [cwd] + list(cwd.parents):
        if (parent / ".git").exists():
            return {"is_git": True, "git_root": str(parent)}
    return {"is_git": False, "git_root": None}


def get_system_context() -> Dict[str, Any]:
    """Gather complete environmental context for shell command synthesis."""
    cwd = Path.cwd()
    sys_name = platform.system()
    distro = platform.platform(terse=True)
    
    # List top files/directories in current path (prioritize visible dirs and files, up to 30)
    sample_files = []
    try:
        entries = list(cwd.iterdir())
        entries.sort(key=lambda p: (p.name.startswith("."), not p.is_dir(), p.name.lower()))
        sample_files = [p.name for p in entries[:30]]
    except Exception:
        pass

    return {
        "os": sys_name,
        "platform": distro,
        "arch": platform.machine(),
        "shell": get_current_shell(),
        "cwd": str(cwd),
        "user": os.environ.get("USER", "user"),
        "git": get_git_info(cwd),
        "directory_sample": sample_files,
    }
