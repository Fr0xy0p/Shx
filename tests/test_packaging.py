"""Tests ensuring package structure and wheel contents are complete."""

from pathlib import Path


def test_every_python_dir_has_init():
    root = Path(__file__).resolve().parent.parent / "shx"
    assert root.is_dir()
    
    missing_init = []
    for path in root.rglob("*"):
        if path.is_dir() and not path.name.startswith((".", "__")):
            # Check if directory contains any .py files
            py_files = list(path.glob("*.py"))
            if py_files:
                init_file = path / "__init__.py"
                if not init_file.exists():
                    missing_init.append(str(path))
                    
    assert not missing_init, f"Directories with .py files missing __init__.py: {missing_init}"
