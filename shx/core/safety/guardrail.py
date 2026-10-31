"""Command safety guardrail engine combining AST analysis with heuristic safety rules."""

import os
import re
from typing import List, Set
from shx.core.safety.rules import (
    RiskLevel,
    RiskReport,
    SafetyRuleViolation,
    CRITICAL_SYSTEM_PATHS,
    SAFE_COMMANDS,
)
from shx.core.safety.ast_analyzer import (
    parse_command_ast,
    unwrap_command,
    ASTAnalysisResult,
)

RAW_DEVICE_PREFIXES = (
    "/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme",
    "/dev/disk", "/dev/rdisk", "/dev/mmcblk", "/dev/mapper/",
    "/dev/dm-", "/dev/md"
)

SENSITIVE_SYSTEM_DIRS = (
    "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64",
    "/System", "/Library", "/root"
)

BENIGN_DEVICES = {
    "/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty"
}

INSECURE_PERM_MODES = {
    "777", "0777", "a+rwx", "a=rwx", "ugo+rwx", "ugo=rwx"
}

SHELL_INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "ksh"
}


def _is_critical_path(path: str) -> bool:
    clean = path.strip()
    if clean in CRITICAL_SYSTEM_PATHS:
        return True

    canon = clean.replace("${HOME}", "~").replace("$HOME", "~")
    if canon in ("~", "~/"):
        return True

    if canon.endswith("/*"):
        base = canon[:-2] or "/"
        base_norm = os.path.normpath(base)
        if base in CRITICAL_SYSTEM_PATHS or base_norm in CRITICAL_SYSTEM_PATHS:
            return True

    if clean in ("/*", "/*.*", "/.", "/..", "/.*") or clean.startswith("/.*"):
        return True

    norm = os.path.normpath(clean)
    if norm in CRITICAL_SYSTEM_PATHS or norm == "/":
        return True

    canon_norm = os.path.normpath(canon)
    if canon_norm in CRITICAL_SYSTEM_PATHS or canon_norm == "~":
        return True

    return False


def _has_recursive_flag(args: List[str]) -> bool:
    return any(
        re.match(r"^-[a-zA-Z]*[rR][a-zA-Z]*$", arg) or arg == "--recursive"
        for arg in args if arg.startswith("-")
    )


class SafetyGuardrail:
    """Evaluates shell commands for destructive patterns, privilege escalation, and unintended side effects."""

    def evaluate(self, command: str) -> RiskReport:
        return self._evaluate_internal(command, depth=0)

    def _evaluate_internal(self, command: str, depth: int = 0) -> RiskReport:
        clean_cmd = command.strip()
        report = RiskReport(command=clean_cmd)

        if not clean_cmd:
            return report

        ast_result = parse_command_ast(clean_cmd)
        report.ast_parsed = ast_result.ast_parsed

        violations: List[SafetyRuleViolation] = []

        # 0. Check AST parse failure fallback notice
        if not ast_result.ast_parsed:
            violations.append(
                SafetyRuleViolation(
                    rule_id="UNPARSED_COMMAND",
                    message="Could not fully parse command with AST analyzer; analysis is best-effort.",
                    severity=RiskLevel.MODERATE,
                    command_token=clean_cmd[:50],
                    rationale="Complex or non-POSIX shell syntax was tokenized using fallback rules.",
                )
            )

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

        # 2. Dangerous: Pipe Remote URL to Shell Interpreter
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
        seen_sudo = False

        for invocation in ast_result.commands:
            raw_cmd = invocation.command
            raw_args = invocation.args

            unwrapped_cmd, unwrapped_args, wrappers = unwrap_command(raw_cmd, raw_args)

            # Check sudo / doas privilege escalation
            if ("sudo" in wrappers or "doas" in wrappers or raw_cmd in ("sudo", "doas")) and not seen_sudo:
                seen_sudo = True
                violations.append(
                    SafetyRuleViolation(
                        rule_id="SUDO_PRIVILEGE",
                        message="Command executes with elevated root/superuser privileges (sudo).",
                        severity=RiskLevel.DANGEROUS,
                        command_token="sudo",
                        rationale="Superuser commands can modify protected system configuration and binaries.",
                    )
                )

            # Analyze recursive payload for shell -c and eval
            if depth < 3:
                inner_payload = ""
                if unwrapped_cmd in SHELL_INTERPRETERS:
                    # Look for -c flag
                    for i, arg in enumerate(unwrapped_args):
                        if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", arg):
                            if i + 1 < len(unwrapped_args):
                                inner_payload = unwrapped_args[i + 1]
                                break
                elif unwrapped_cmd == "eval":
                    inner_payload = " ".join(unwrapped_args)
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="EVAL_EXEC",
                            message="Executing dynamic payload with 'eval'.",
                            severity=RiskLevel.DANGEROUS,
                            command_token="eval",
                            rationale="Dynamic code execution with eval obscures command intent and bypasses static controls.",
                        )
                    )
                elif unwrapped_cmd == "exec":
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="EVAL_EXEC",
                            message="Replacing current shell process with 'exec'.",
                            severity=RiskLevel.DANGEROUS,
                            command_token="exec",
                            rationale="Replaces process environment directly.",
                        )
                    )

                if inner_payload.strip():
                    inner_report = self._evaluate_internal(inner_payload.strip(), depth=depth + 1)
                    violations.extend(inner_report.violations)

            # Check rm commands (recursive deletions)
            if unwrapped_cmd == "rm":
                self._check_rm_safety(unwrapped_args, violations)

            # Check chmod / chown
            elif unwrapped_cmd in ("chmod", "chown"):
                self._check_permission_safety(unwrapped_cmd, unwrapped_args, violations)

            # Check dd / raw disk writes
            elif unwrapped_cmd == "dd":
                self._check_dd_safety(unwrapped_args, violations)

            # Check filesystem formatting & partitioning
            elif unwrapped_cmd.startswith("mkfs"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="DISK_FORMATTING",
                        message=f"Low-level filesystem creation tool '{unwrapped_cmd}'.",
                        severity=RiskLevel.CRITICAL,
                        command_token=unwrapped_cmd,
                        rationale="Permanently formats storage drives and erases existing filesystems.",
                    )
                )
            elif unwrapped_cmd in ("fdisk", "gdisk", "sfdisk", "parted"):
                is_list_only = any(a in ("-l", "--list", "-ls", "print", "p") for a in unwrapped_args)
                if not is_list_only:
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="DISK_FORMATTING",
                            message=f"Low-level disk partitioning tool '{unwrapped_cmd}'.",
                            severity=RiskLevel.CRITICAL,
                            command_token=unwrapped_cmd,
                            rationale="Can permanently alter or delete disk partition tables.",
                        )
                    )

            # Check destructive git commands
            elif unwrapped_cmd == "git":
                self._check_git_safety(unwrapped_args, violations)

            # Check process kill commands
            elif unwrapped_cmd in ("killall", "pkill"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="PROCESS_MASS_KILL",
                        message=f"Terminating multiple processes with '{unwrapped_cmd}'.",
                        severity=RiskLevel.MODERATE,
                        command_token=unwrapped_cmd,
                        rationale="May unintentionally terminate dependent services or unsaved work.",
                    )
                )
            elif unwrapped_cmd == "kill":
                self._check_kill_safety(unwrapped_args, violations)

            # Check find destructive options (-delete, -exec rm)
            elif unwrapped_cmd == "find":
                self._check_find_safety(unwrapped_args, violations, depth)

            # Check shred, wipefs, truncate
            elif unwrapped_cmd in ("shred", "wipefs", "truncate"):
                self._check_shred_safety(unwrapped_cmd, unwrapped_args, violations)

            # Check system shutdown / reboot
            elif unwrapped_cmd in ("shutdown", "reboot", "halt", "poweroff"):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="SYSTEM_SHUTDOWN",
                        message=f"System power control command '{unwrapped_cmd}'.",
                        severity=RiskLevel.DANGEROUS,
                        command_token=unwrapped_cmd,
                        rationale="Shuts down or reboots the host operating system.",
                    )
                )
            elif unwrapped_cmd == "init" and any(a in ("0", "6") for a in unwrapped_args):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="SYSTEM_SHUTDOWN",
                        message=f"System state transition 'init {unwrapped_args[0]}'.",
                        severity=RiskLevel.DANGEROUS,
                        command_token=f"init {unwrapped_args[0]}",
                        rationale="Halts or reboots the system via init runlevels.",
                    )
                )
            elif unwrapped_cmd == "systemctl" and any(a in ("poweroff", "reboot", "halt") for a in unwrapped_args):
                sub = next(a for a in unwrapped_args if a in ("poweroff", "reboot", "halt"))
                violations.append(
                    SafetyRuleViolation(
                        rule_id="SYSTEM_SHUTDOWN",
                        message=f"Systemd service manager command 'systemctl {sub}'.",
                        severity=RiskLevel.DANGEROUS,
                        command_token=f"systemctl {sub}",
                        rationale="Triggers machine shutdown or restart.",
                    )
                )

            # Check crontab -r
            elif unwrapped_cmd == "crontab" and any(re.match(r"^-[a-zA-Z]*r", a) for a in unwrapped_args):
                violations.append(
                    SafetyRuleViolation(
                        rule_id="CRONTAB_REMOVE",
                        message="Removing user crontab schedule ('crontab -r').",
                        severity=RiskLevel.DANGEROUS,
                        command_token="crontab -r",
                        rationale="Permanently deletes all scheduled cron automation without confirmation.",
                    )
                )

            # Check tee overwriting system files
            elif unwrapped_cmd == "tee":
                target_paths = [a for a in unwrapped_args if not a.startswith("-")]
                for p in target_paths:
                    if any(p == s or p.startswith(s + "/") for s in SENSITIVE_SYSTEM_DIRS):
                        violations.append(
                            SafetyRuleViolation(
                                rule_id="SYSTEM_FILE_OVERWRITE",
                                message=f"Writing to protected system file '{p}' via tee.",
                                severity=RiskLevel.DANGEROUS,
                                command_token=f"tee {p}",
                                rationale="May corrupt OS system files.",
                            )
                        )

            # Check mv / cp onto critical paths or /dev/null
            elif unwrapped_cmd in ("mv", "cp"):
                self._check_mv_cp_safety(unwrapped_cmd, unwrapped_args, violations)

        # 4. Check Redirection Overwrites
        for redirect in ast_result.redirects:
            target = redirect.get("target", "")
            rtype = redirect.get("type", "")
            if rtype in (">", ">|", ">>", "&>", "&>>"):
                if target in BENIGN_DEVICES or target.startswith("/dev/fd/"):
                    continue

                if any(target.startswith(d) for d in RAW_DEVICE_PREFIXES):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="RAW_DEVICE_OVERWRITE",
                            message=f"Overwriting raw block storage device '{target}'.",
                            severity=RiskLevel.CRITICAL,
                            command_token=f"{rtype} {target}",
                            rationale="Direct device overwrite destroys raw filesystem metadata and sectors.",
                        )
                    )
                elif any(target == p or target.startswith(p + "/") for p in SENSITIVE_SYSTEM_DIRS):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="SYSTEM_FILE_OVERWRITE",
                            message=f"Redirecting output to overwrite system file '{target}'.",
                            severity=RiskLevel.DANGEROUS,
                            command_token=f"{rtype} {target}",
                            rationale="May corrupt OS system files.",
                        )
                    )

        # Deduplicate violations by rule_id + command_token
        unique_violations: List[SafetyRuleViolation] = []
        seen_keys: Set[tuple] = set()
        for v in violations:
            key = (v.rule_id, v.command_token)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_violations.append(v)

        report.violations = unique_violations
        report.level = self._compute_overall_level(clean_cmd, unique_violations, ast_result)
        report.score = self._compute_score(report.level, unique_violations)
        report.is_blocked = (report.level == RiskLevel.CRITICAL)

        return report

    def _check_rm_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        is_recursive = _has_recursive_flag(args)

        target_paths: List[str] = []
        in_double_dash = False
        for a in args:
            if in_double_dash:
                target_paths.append(a)
            elif a == "--":
                in_double_dash = True
            elif not a.startswith("-"):
                target_paths.append(a)

        has_critical = False
        for path in target_paths:
            if _is_critical_path(path):
                has_critical = True
                violations.append(
                    SafetyRuleViolation(
                        rule_id="CRITICAL_PATH_DELETION",
                        message=f"Attempting recursive/direct deletion of critical path '{path}'.",
                        severity=RiskLevel.CRITICAL,
                        command_token=f"rm {path}",
                        rationale="Deleting root or system paths renders the operating system unbootable.",
                    )
                )
                break

        if not has_critical:
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
        is_recursive = _has_recursive_flag(args)

        target_paths = [a for a in args if not a.startswith("-")]

        if cmd == "chmod":
            has_777 = any(arg in INSECURE_PERM_MODES for arg in args)
            if has_777:
                has_critical_target = any(_is_critical_path(p) for p in target_paths)
                severity = RiskLevel.CRITICAL if (is_recursive or has_critical_target) else RiskLevel.DANGEROUS
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
            has_root = any(a == "root" or a.startswith("root:") for a in args)
            if is_recursive and has_root:
                has_critical_target = any(_is_critical_path(p) for p in target_paths)
                severity = RiskLevel.CRITICAL if has_critical_target else RiskLevel.DANGEROUS
                violations.append(
                    SafetyRuleViolation(
                        rule_id="RECURSIVE_ROOT_CHOWN",
                        message="Recursively transferring ownership to root.",
                        severity=severity,
                        command_token="chown -R root",
                        rationale="Can lock user out of workspace or project folders.",
                    )
                )

    def _check_dd_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        for arg in args:
            if arg.startswith("of="):
                dest = arg[3:]
                if dest in BENIGN_DEVICES or dest.startswith("/dev/fd/"):
                    continue
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

        GLOBAL_VALUED_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg in GLOBAL_VALUED_OPTS:
                idx += 2
            elif any(arg.startswith(opt + "=") for opt in GLOBAL_VALUED_OPTS):
                idx += 1
            elif arg.startswith("-"):
                idx += 1
            else:
                break

        if idx >= len(args):
            return

        subcmd = args[idx]
        subcmd_args = args[idx + 1:]

        if subcmd == "reset" and "--hard" in subcmd_args:
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_HARD_RESET",
                    message="Hard reset ('git reset --hard') discards all uncommitted working changes.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="git reset --hard",
                    rationale="Uncommitted code in working tree will be permanently wiped.",
                )
            )
        elif subcmd == "clean":
            if not any(a in ("-n", "--dry-run") for a in subcmd_args):
                if any(re.match(r"^-[a-zA-Z]*f", a) or a == "--force" for a in subcmd_args):
                    violations.append(
                        SafetyRuleViolation(
                            rule_id="GIT_CLEAN_FORCE",
                            message="Force cleaning untracked files from git repository.",
                            severity=RiskLevel.MODERATE,
                            command_token="git clean -f",
                            rationale="Deletes untracked local files.",
                        )
                    )
        elif subcmd == "push":
            is_force = (
                any(a in ("--force", "-f", "--force-with-lease", "--force-if-includes", "--mirror") for a in subcmd_args)
                or any(a.startswith("+") for a in subcmd_args)
            )
            if is_force:
                violations.append(
                    SafetyRuleViolation(
                        rule_id="GIT_FORCE_PUSH",
                        message="Force-pushing to remote git repository.",
                        severity=RiskLevel.DANGEROUS,
                        command_token="git push --force",
                        rationale="May overwrite coworkers' commits on remote branch.",
                    )
                )
        elif subcmd in ("checkout", "restore"):
            if "." in subcmd_args:
                violations.append(
                    SafetyRuleViolation(
                        rule_id="GIT_DISCARD_WORKTREE",
                        message=f"Discarding local changes across working tree ('git {subcmd} .').",
                        severity=RiskLevel.DANGEROUS,
                        command_token=f"git {subcmd} .",
                        rationale="Permanently reverts uncommitted modifications across the repository.",
                    )
                )
        elif subcmd == "branch" and "-D" in subcmd_args:
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_BRANCH_FORCE_DELETE",
                    message="Force deleting git branch ('git branch -D').",
                    severity=RiskLevel.MODERATE,
                    command_token="git branch -D",
                    rationale="Deletes git branch regardless of merged status.",
                )
            )
        elif subcmd == "stash" and any(a in ("clear", "drop") for a in subcmd_args):
            violations.append(
                SafetyRuleViolation(
                    rule_id="GIT_STASH_DROP",
                    message=f"Dropping or clearing saved git stash ('git stash {subcmd_args[0]}').",
                    severity=RiskLevel.MODERATE,
                    command_token=f"git stash {subcmd_args[0]}",
                    rationale="Removes stashed changes from repository stash stack.",
                )
            )

    def _check_kill_safety(self, args: List[str], violations: List[SafetyRuleViolation]):
        is_sigkill = any(
            a in ("-9", "SIGKILL", "-KILL", "-SIGKILL")
            for a in args
        )
        for i, a in enumerate(args):
            if a == "-s" and i + 1 < len(args) and args[i + 1] in ("9", "KILL", "SIGKILL"):
                is_sigkill = True

        if is_sigkill:
            if "-1" in args:
                violations.append(
                    SafetyRuleViolation(
                        rule_id="FORCE_KILL_ALL",
                        message="Sending non-catchable SIGKILL to all processes ('kill -9 -1').",
                        severity=RiskLevel.DANGEROUS,
                        command_token="kill -9 -1",
                        rationale="Terminates all user processes immediately.",
                    )
                )
            else:
                violations.append(
                    SafetyRuleViolation(
                        rule_id="FORCE_KILL",
                        message="Sending non-catchable SIGKILL (-9) to process.",
                        severity=RiskLevel.MODERATE,
                        command_token="kill -9",
                        rationale="Process cannot perform cleanup routines before exit.",
                    )
                )

    def _check_find_safety(self, args: List[str], violations: List[SafetyRuleViolation], depth: int):
        if "-delete" in args:
            violations.append(
                SafetyRuleViolation(
                    rule_id="FIND_DELETE",
                    message="Direct recursive file deletion with 'find -delete'.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="find -delete",
                    rationale="Directly erases files matching find filters.",
                )
            )
        if "-exec" in args:
            idx = args.index("-exec")
            inner_tokens: List[str] = []
            for tok in args[idx + 1:]:
                if tok in (";", "+", "\\;", "\\+"):
                    break
                inner_tokens.append(tok)
            if inner_tokens and depth < 3:
                inner_cmd = " ".join(inner_tokens).replace("{}", "placeholder")
                inner_report = self._evaluate_internal(inner_cmd, depth=depth + 1)
                violations.extend(inner_report.violations)

    def _check_shred_safety(self, cmd: str, args: List[str], violations: List[SafetyRuleViolation]):
        targets = [a for a in args if not a.startswith("-")]
        is_critical = False
        for t in targets:
            if _is_critical_path(t) or any(t.startswith(d) for d in RAW_DEVICE_PREFIXES):
                is_critical = True
                break

        severity = RiskLevel.CRITICAL if is_critical else RiskLevel.DANGEROUS
        violations.append(
            SafetyRuleViolation(
                rule_id="DATA_DESTRUCTION",
                message=f"Secure deletion/truncation tool '{cmd}' destroys target contents.",
                severity=severity,
                command_token=cmd,
                rationale="Overwrites and permanently destroys file or device data blocks.",
            )
        )

    def _check_mv_cp_safety(self, cmd: str, args: List[str], violations: List[SafetyRuleViolation]):
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return
        dest = targets[-1]
        if dest == "/dev/null" and cmd == "mv":
            violations.append(
                SafetyRuleViolation(
                    rule_id="FILE_DELETION",
                    message="Moving files directly to '/dev/null'.",
                    severity=RiskLevel.DANGEROUS,
                    command_token="mv /dev/null",
                    rationale="Effectively deletes files by redirecting to bitbucket.",
                )
            )
        elif _is_critical_path(dest):
            violations.append(
                SafetyRuleViolation(
                    rule_id="CRITICAL_PATH_OVERWRITE",
                    message=f"Overwriting or copying into critical system path '{dest}'.",
                    severity=RiskLevel.DANGEROUS,
                    command_token=f"{cmd} {dest}",
                    rationale="Modifying system root directories can destabilize host OS.",
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

        # If no violations exist, verify that EVERY command invocation is in SAFE_COMMANDS
        if not ast_result.commands:
            return RiskLevel.SAFE

        for invocation in ast_result.commands:
            unwrapped_cmd, unwrapped_args, _ = unwrap_command(invocation.command, invocation.args)
            if unwrapped_cmd == "git":
                subcmd = unwrapped_args[0] if unwrapped_args else ""
                git_full = f"git {subcmd}".strip()
                if git_full not in SAFE_COMMANDS:
                    return RiskLevel.MODERATE
            elif unwrapped_cmd not in SAFE_COMMANDS:
                return RiskLevel.MODERATE

        return RiskLevel.SAFE

    def _compute_score(self, level: RiskLevel, violations: List[SafetyRuleViolation]) -> int:
        if level == RiskLevel.CRITICAL:
            return 100
        if level == RiskLevel.DANGEROUS:
            return min(85, 50 + len(violations) * 15)
        if level == RiskLevel.MODERATE:
            return min(45, 20 + len(violations) * 10)
        return 0
