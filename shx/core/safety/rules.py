"""Safety rules, risk levels, and risk reporting."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"            # Read-only, inspection, status
    MODERATE = "MODERATE"    # Local changes, installations, safe edits
    DANGEROUS = "DANGEROUS"  # File deletions, sudo, process termination
    CRITICAL = "CRITICAL"    # Root destruction, disk formatting, fork bombs


class SafetyRuleViolation(BaseModel):
    rule_id: str
    message: str
    severity: RiskLevel
    command_token: str = ""
    rationale: str = ""


class RiskReport(BaseModel):
    command: str
    level: RiskLevel = RiskLevel.SAFE
    score: int = Field(default=0, ge=0, le=100)
    violations: List[SafetyRuleViolation] = Field(default_factory=list)
    ast_parsed: bool = True
    is_blocked: bool = False

    @property
    def is_safe(self) -> bool:
        return self.level == RiskLevel.SAFE

    @property
    def needs_warning(self) -> bool:
        return self.level in (RiskLevel.DANGEROUS, RiskLevel.CRITICAL)


# Read-only safe commands
SAFE_COMMANDS = {
    "ls", "cat", "grep", "egrep", "fgrep", "rg", "ag", "find",
    "head", "tail", "less", "more", "wc", "sort", "uniq",
    "pwd", "echo", "printf", "diff", "cmp", "file", "stat",
    "du", "df", "free", "uptime", "uname", "whoami", "id",
    "ps", "top", "htop", "which", "whereis", "type", "man",
    "git status", "git log", "git diff", "git show", "git branch",
    "date", "cal", "printenv", "history",
}

# Critical system directories that must never be wiped or modified recursively
CRITICAL_SYSTEM_PATHS = {
    "/", "/*", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
    "/root", "/sbin", "/sys", "/usr", "/usr/bin", "/usr/sbin",
    "/usr/local", "/usr/lib", "/usr/share", "/var", "/var/lib",
    "/home", "/Users", "/opt", "/mnt", "/media", "/srv",
    "/Volumes", "/private", "/proc", "/run",
    "/Library", "/System", "/Applications",
    "~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/",
}
