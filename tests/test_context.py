"""Unit tests for context detection, git repositories, submodules, and worktrees."""

from shx.core.context import get_git_info


def test_git_repo_directory(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    nested = repo_dir / "src" / "deep"
    nested.mkdir(parents=True)

    info = get_git_info(nested)
    assert info["is_git"] is True
    assert info["git_root"] == str(repo_dir)


def test_git_worktree_or_submodule_file(tmp_path):
    worktree_dir = tmp_path / "worktree"
    worktree_dir.mkdir()
    git_file = worktree_dir / ".git"
    git_file.write_text("gitdir: /path/to/main/.git/worktrees/wt\n", encoding="utf-8")

    sub = worktree_dir / "subdir"
    sub.mkdir()

    info = get_git_info(sub)
    assert info["is_git"] is True
    assert info["git_root"] == str(worktree_dir)


def test_non_git_directory(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    info = get_git_info(plain)
    assert info["is_git"] is False
    assert info["git_root"] is None

