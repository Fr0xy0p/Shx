#!/usr/bin/env python3
"""Build a standalone binary for shx using PyInstaller."""

import subprocess
import sys
from pathlib import Path


def main():
    root_dir = Path(__file__).resolve().parent.parent
    cli_entry = root_dir / "shx" / "cli.py"

    print("Checking for PyInstaller...")
    try:
        import PyInstaller
    except ImportError:
        print("Installing pyinstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=shx",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--collect-all=bashlex",
        "--collect-all=rich",
        "--collect-all=typer",
        str(cli_entry),
    ]

    print("Running PyInstaller command:")
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=root_dir)

    binary_path = root_dir / "dist" / "shx"
    print(f"\n✔ Standalone binary built successfully at: {binary_path}")
    print(f"To test: {binary_path} --help")


if __name__ == "__main__":
    main()

