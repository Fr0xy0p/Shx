"""Unit tests for offline cryptic flag explainer."""

from shx.core.explainer import explain_local_command


def test_tar_flags():
    flags = explain_local_command("tar -xzvf archive.tar.gz")
    flag_strings = [f.flag for f in flags]
    assert "tar -x" in flag_strings
    assert "tar -z" in flag_strings
    assert "tar -v" in flag_strings
    assert "tar -f" in flag_strings


def test_rsync_flags():
    flags = explain_local_command("rsync -avzP --delete src/ dest/")
    flag_strings = [f.flag for f in flags]
    assert "rsync -a" in flag_strings
    assert "rsync -v" in flag_strings
    assert "rsync -z" in flag_strings
    assert "rsync -P" in flag_strings
    assert "rsync --delete" in flag_strings


def test_find_flags():
    flags = explain_local_command("find /tmp -type f -mtime +7 -delete")
    flag_strings = [f.flag for f in flags]
    assert "find -type" in flag_strings
    assert "find -mtime" in flag_strings
    assert "find -delete" in flag_strings
