"""Command safety guardrail engine combining AST analysis with heuristic safety rules."""

import os
import re
from pathlib import Path
from typing import List
from shx.core.safety.rules import (
    RiskLevel,
    RiskReport,
    SafetyRuleViolation,
    CRITICAL_SYSTEM_PATHS,
    SAFE_COMMANDS,
)
from shx.core.safety.ast_analyzer import parse_command_ast, ASTAnalysisResult


class SafetyGuardrail:
    """Evaluates shell commands for destructive patterns, privilege escalation, and unintended side effects."""

    def evaluate(self, command: str) -> RiskReport:
        clean_cmd = command.strip()
        report = RiskReport(command=clean_cmd)

        if not clean_cmd:
            return report

        ast_result = parse_command_ast(clean_cmd)
        report.ast_parsed = (ast_result.raw_error is None)

        violations: List[SafetyRuleViolation] = []

        # 1. Critical: Fork Bomb Check
        if ast_result.is_fork_bomb:
            violations.append(
                SafetyRuleViolation(
                    rule_id="FORK_BOMB",
                    message="Detected bash fork-bomb pattern that would freeze system resources.",
                    severity=RiskLevel.CRITICAL,
                    command_token=clean_cmd,
                    rationale="Fork bombs exponentially spawn processes until system memory/PID exhaustion.",
                )
            )

        # 2. Critical: Pipe Remote URL to Shell Interpreter
        if ast_result.has_pipe_to_shell:
            violations.append(
                SafetyRuleViolation(
                    rule_id="REMOTE_EXEC_PIPE",
                    message="Piping untrusted remote or dynamic content directly into a shell interpreter.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="| shell",
                    rationale="Executing remote scripts blindly can compromise host integrity.",
                )
            )

        # 3. Analyze each command invocation in AST
        for invocation in ast_result.commands:
            cmd = invocation.command
            args = invocation.args

            # Check sudo escalation
            if cmd == "sudo":
                violations.append(
                    SafetyRuleViolation(
                        rule_id="SUDO_PRIVILEGE",
                        message="Command executes with elevated root/superuser privileges (sudo).",
                        severity=RiskLevel.DANGEROUS,
                        command_token="sudo",
                        rationale="Superuser commands can modify protected system configuration and binaries.",
                    )
                )
                # Unwrap sudo if inner command exists
                if args:
                    cmd = args[0]
                    args = args[1:]

            # Check rm commands (recursive deletions)
            if cmd == "rm":
                self._check_rm_safety(args, violations)

            # Check chmod / chown
            elif cmd in ("chmod", "chown"):
                self._check_permission_safety(cmd, args, violations)

            # Check dd / raw disk writes
            elif cmd == "dd":
                self._check_dd_safety(args, violations)

            # Check filesystem formatting
            elif cmd.startswith("mkfs") or cmd in ("fdisk", "gdisk", "parted"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="DISK_FORMATTING",
                        message=f"Low-level disk partitioning/formatting tool '{cmd}'.",
                        severity=RiskLevel.CRITICAL,
                        command_token=cmd,
                        rationale="Can permanently destroy disk partition tables and file structures.",
                    )
                )

            # Check destructive git commands
            elif cmd == "git":
                self._check_git_safety(args, violations)

            # Check process kill all
            elif cmd in ("killall", "pkill"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="PROCESS_MASS_KILL",
                        message=f"Terminating multiple processes with '{cmd}'.",
                        severity=RiskLevel.MODERATE,
                        command_token=cmd,
                        rationale="May unintentionally terminate dependent services or unsaved work.",
                    )
                )
            elif cmd == "kill":
                if "-9" in args or "SIGKILL" in args:
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="FORCE_KILL",
                            message="Sending non-catchable SIGKILL (-9) to process.",
                            severity=RiskLevel.MODERATE,
                            command_token="kill -9",
                            rationale="Process cannot perform cleanup routines before exit.",
                        )
                    )

        # 4. Check Redirection Overwrites to Block Devices or Sensitive Paths
        for redirect in ast_result.redirects:
            target = redirect.get("target", "")
            rtype = redirect.get("type", "")
            if rtype in (">", ">|"):
                if target.startswith("/dev/sd") or target.startswith("/dev/nvme") or target.startswith("/dev/disk"):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="RAW_DEVICE_OVERWRITE",
                            message=f"Overwriting raw block storage device '{target}'.",
                            severity=RiskLevel.CRITICAL,
                            command_token=f"> {target}",
                            rationale="Direct device overwrite destroys raw filesystem metadata and sectors.",
                        )
                    )
                elif target in ("/dev/null", "/dev/zero"):
                    pass  # Normal redirection
                elif target.startswith("/etc") or target.startswith("/usr") or target.startswith("/bin"):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="SYSTEM_FILE_OVERWRITE",
                            message=f"Redirecting output to overwrite system file '{target}'.",
                            severity=RiskLevel.DANGEROUS,
                            command_token=f"> {target}",
                            rationale="May corrupt OS system files.",
                        )
                    )

        # Aggregate risk score and highest severity level
        report.violations = violations
        report.level = self._compute_overall_level(clean_cmd, violations, ast_result)
        report.score = self._compute_score(report.level, violations)
        report.is_blocked = (report.level == RiskLevel.CRITICAL)

        return report

    def _check_rm_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        is_recursive = any(
            re.match(r"^-[a-zA-Z]*[rR]", arg) or arg in ("--recursive", "-r", "-R", "-rf", "-fr")
            for arg in args
        )
        is_force = any(
            re.match(r"^-[a-zA-Z]*f", arg) or arg in ("-f", "--force", "-rf", "-fr")
            for arg in args
        )

        target_paths = [a for a in args if not a.startswith("-")]

        for path in target_paths:
            normalized = os.path.normpath(path)
            # Check critical system paths
            if path in CRITICAL_SYSTEM_PATHS or normalized in CRITICAL_SYSTEM_PATHS or normalized == "/":
                violations.append(
                    SafetyRuleViolation(
                        rule_id="CRITICAL_PATH_DELETION",
                        message=f"Attempting recursive/direct deletion of critical path '{path}'.",
                        severity=RiskLevel.CRITICAL,
                        command_token=f"rm {path}",
                        rationale="Deleting root or system paths renders the operating system unbootable.",
                    )
                )
                return

            # Wildcard root check: rm -rf /* or rm -rf /etc/*
            if path in ("/*", "/*.*", "/.", "/..") or path.startswith("/*"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="ROOT_WILDCARD_DELETION",
                        message=f"Wildcard deletion targeting root directory '{path}'.",
                        severity=RiskLevel.CRITICAL,
                        command_token=f"rm {path}",
                        rationale="Recursive root wildcard deletion erases all mounted drives.",
                    )
                )
                return

        if is_recursive:
            violations.append(
                SafetyRuleViolation(
                    rule_id="RECURSIVE_DELETION",
                    message="Recursive directory deletion ('rm -r' / 'rm -rf').",
                    severity=RiskLevel.DANGEROUS,
                    command_token="rm -r",
                    rationale="Files deleted via terminal bypass Trash and cannot be recovered via undo.",
                )
            )
        else:
            violations.append(
                SafetyRuleViolation(
                    rule_id="FILE_DELETION",
                    message="Standard permanent file removal ('rm').",
                    severity=RiskLevel.MODERATE,
                    command_token="rm",
                    rationale="Permanent deletion of files.",
                )
            )

    def _check_permission_safety(self, cmd: str, args: List[str], violations: List[SafetyRuleViolation]):
        if cmd == "chmod":
            if any(arg in ("777", "a+rwx", "-R 777", "0777") for arg in args):
                is_recursive = any("-R" in a or "--recursive" in a for a in args)
                severity = RiskLevel.CRITICAL if is_recursive else RiskLevel.DANGEROUS
                violations.append(
                    SafetyRuleViolation(
                        rule_id="INSECURE_PERMISSIONS_777",
                        message="Setting global read, write, and execute permissions (777).",
                        severity=severity,
                        command_token="chmod 777",
                        rationale="Allows any local user or malicious process to modify or execute files.",
                    )
                )
        elif cmd == "chown":
            if any("-R" in a for a in args) and any(a in ("root", "root:root") for a in args):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="RECURSIVE_ROOT_CHOWN",
                        message="Recursively transferring ownership to root.",
                        severity=RiskLevel.DANGEROUS,
                        command_token="chown -R root",
                        rationale="Can lock user out of workspace or project folders.",
                    )
                )

    def _check_dd_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        for arg in args:
            if arg.startswith("of="):
                dest = arg[3:]
                if dest.startswith("/dev/"):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="DD_DISK_OVERWRITE",
                            message=f"dd output target '{dest}' directly writes to physical/virtual device.",
                            severity=RiskLevel.CRITICAL,
                            command_token=arg,
                            rationale="Overwrites disk blocks without filesystem safety checks.",
                        )
                    )

    def _check_git_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        if not args:
            return
        subcmd = args[0]
        if subcmd == "reset" and "--hard" in args:
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_HARD_RESET",
                    message="Hard reset ('git reset --hard') discards all uncommitted working changes.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="git reset --hard",
                    rationale="Uncommitted code in working tree will be permanently wiped.",
                )
            )
        elif subcmd == "clean" and any("-f" in a for a in args):
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_CLEAN_FORCE",
                    message="Force cleaning untracked files from git repository.",
                    severity=RiskLevel.MODERATE,
                    command_token="git clean -f",
                    rationale="Deletes untracked local files.",
                )
            )
        elif subcmd == "push" and any(a in ("--force", "-f", "--force-with-lease") for a in args):
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_FORCE_PUSH",
                    message="Force-pushing to remote git repository.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="git push --force",
                    rationale="May overwrite coworkers' commits on remote branch.",
                )
            )

    def _compute_overall_level(self, command: str, violations: List[SafetyRuleViolation], ast_result: ASTAnalysisResult) -> RiskLevel:
        severities = [v.severity for v in violations]
        if RiskLevel.CRITICAL in severities:
            return RiskLevel.CRITICAL
        if RiskLevel.DANGEROUS in severities:
            return RiskLevel.DANGEROUS
        if RiskLevel.MODERATE in severities:
            return RiskLevel.MODERATE

        # If no violations, check if command is in safe read-only list
        first_cmd = ast_result.commands[0].command if ast_result.commands else command.split()[0] if command.split() else ""
        if first_cmd in SAFE_COMMANDS or command in SAFE_COMMANDS:
            return RiskLevel.SAFE

        return RiskLevel.SAFE

    def _compute_score(self, level: RiskLevel, violations: List[SafetyRuleViolation]) -> int:
        if level == RiskLevel.CRITICAL:
            return 100
        if level == RiskLevel.DANGEROUS:
            return min(85, 50 + len(violations) * 15)
        if level == RiskLevel.MODERATE:
            return min(45, 20 + len(violations) * 10)
        return 0
