"""Unit tests for offline cryptic flag explainer."""

from shx.core.explainer import explain_local_command


def test_tar_flags():
    flags = explain_local_command("tar -xzvf archive.tar.gz")
    flag_strings = [f.flag for f in flags]
    assert "tar -x" in flag_strings
    assert "tar -z" in flag_strings
    assert "tar -v" in flag_strings
    assert "tar -f" in flag_strings


def test_dashless_tar_flags():
    flags1 = explain_local_command("tar xzvf a.tgz")
    flag_strings1 = [f.flag for f in flags1]
    assert "tar -x" in flag_strings1
    assert "tar -z" in flag_strings1
    assert "tar -v" in flag_strings1
    assert "tar -f" in flag_strings1

    flags2 = explain_local_command("tar czf out.tgz dir")
    flag_strings2 = [f.flag for f in flags2]
    assert "tar -c" in flag_strings2
    assert "tar -z" in flag_strings2
    assert "tar -f" in flag_strings2


def test_ps_aux_variants():
    flags = explain_local_command("ps -aux")
    assert any("ps" in f.flag for f in flags)

    flags_bare = explain_local_command("ps aux")
    assert any("ps" in f.flag for f in flags_bare)


def test_sudo_and_pipeline_boundaries():
    flags_sudo = explain_local_command("sudo tar -xzvf a.tgz")
    flag_strings_sudo = [f.flag for f in flags_sudo]
    assert "tar -x" in flag_strings_sudo
    assert "tar -z" in flag_strings_sudo

    flags_pipe = explain_local_command("cat f|grep -in x")
    flag_strings_pipe = [f.flag for f in flags_pipe]
    assert "grep -i" in flag_strings_pipe
    assert "grep -n" in flag_strings_pipe


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
