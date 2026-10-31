"""Cryptic flag dictionary and command explainer engine."""

import shlex
from typing import Dict, List, Tuple
from pydantic import BaseModel
from shx.core.safety.ast_analyzer import unwrap_command


class FlagInfo(BaseModel):
    flag: str
    name: str
    description: str


# Offline database of notoriously cryptic Unix/POSIX/GNU/BSD flags
CRYPTIC_FLAG_DATABASE: Dict[str, Dict[str, Tuple[str, str]]] = {
    "tar": {
        "-x": ("Extract", "Extract files from an archive"),
        "-c": ("Create", "Create a new archive"),
        "-v": ("Verbose", "Verbosely list files processed"),
        "-z": ("Gzip", "Filter archive through gzip (.tar.gz / .tgz)"),
        "-j": ("Bzip2", "Filter archive through bzip2 (.tar.bz2)"),
        "-J": ("XZ", "Filter archive through xz (.tar.xz)"),
        "-f": ("File", "Use given archive file instead of tape drive"),
        "-p": ("Preserve Permissions", "Preserve file permissions/modes"),
        "-C": ("Change Directory", "Change to target directory before performing operations"),
        "--strip-components": ("Strip Leading Components", "Remove leading directory components from file names"),
        "-t": ("List", "List archive contents without extracting"),
    },
    "find": {
        "-type": ("File Type", "Filter by type (f = regular file, d = directory, l = symlink)"),
        "-name": ("Name Pattern", "Case-sensitive filename pattern matching"),
        "-iname": ("Case-Insensitive Name", "Case-insensitive filename pattern matching"),
        "-mtime": ("Modified Time", "Files modified n*24 hours ago (+n = older than, -n = newer than)"),
        "-mmin": ("Modified Minutes", "Files modified n minutes ago"),
        "-size": ("File Size", "Filter by size (+100M = larger than 100MB, -1k = less than 1KB)"),
        "-exec": ("Execute Command", "Execute command on each match (terminated with ';' or '+')"),
        "-delete": ("Delete Matches", "Permanently delete matching files directly"),
        "-maxdepth": ("Max Recursion Depth", "Descend at most n directory levels below starting point"),
        "-perm": ("Permissions", "Find files matching specific permission mode bits"),
        "-empty": ("Empty File/Directory", "Find files or directories that are zero bytes / empty"),
    },
    "rsync": {
        "-a": ("Archive Mode", "Equivalent to -rlptgoD (recursive, copy symlinks, preserve perms, times, owner, group)"),
        "-v": ("Verbose", "Increase verbosity"),
        "-z": ("Compress", "Compress file data during transfer"),
        "-P": ("Progress & Partial", "Equivalent to --partial --progress (keep partially transferred files and show progress)"),
        "--delete": ("Delete Extraneous", "Delete files in destination that do not exist in source"),
        "-e": ("Remote Shell", "Specify remote shell to use (e.g., ssh)"),
        "-h": ("Human-Readable", "Output numbers in human-readable format"),
        "-n": ("Dry Run", "Perform trial run with no changes made"),
        "--exclude": ("Exclude Pattern", "Exclude files matching pattern"),
    },
    "curl": {
        "-s": ("Silent", "Silent mode (don't show progress bar or error messages)"),
        "-S": ("Show Error", "When used with -s, makes curl show error message if it fails"),
        "-L": ("Follow Redirects", "Follow HTTP 3xx redirects automatically"),
        "-O": ("Remote Name", "Write output to local file named like remote file"),
        "-o": ("Output File", "Write output to specific file"),
        "-X": ("Request Method", "Specify custom request method (GET, POST, PUT, DELETE)"),
        "-H": ("Header", "Pass custom HTTP header to server"),
        "-d": ("Data", "HTTP POST data"),
        "-k": ("Insecure", "Allow insecure SSL connections (skip certificate verification)"),
        "-I": ("Head Request", "Fetch HTTP headers only"),
    },
    "chmod": {
        "-R": ("Recursive", "Change files and directories recursively"),
        "777": ("Read/Write/Execute for All", "Owner, Group, and Others have full permissions (insecure)"),
        "755": ("Owner Full, Others Read/Exec", "Standard permissions for executable scripts/directories"),
        "644": ("Owner Read/Write, Others Read", "Standard safe permissions for regular files"),
        "600": ("Owner Read/Write Only", "Strict permissions for private SSH keys / config"),
        "+x": ("Make Executable", "Add executable permission for user/group/others"),
    },
    "awk": {
        "-F": ("Field Separator", "Define input field separator delimiter (e.g. -F: for /etc/passwd)"),
        "-v": ("Variable Assignment", "Assign value to variable before execution"),
    },
    "sed": {
        "-i": ("In-place Edit", "Edit files in place (on macOS, requires '' argument like -i '')"),
        "-e": ("Script Expression", "Add script command to be executed"),
        "-n": ("Suppress Printing", "Suppress automatic printing of pattern space"),
    },
    "ps": {
        "aux": ("All Processes BSD", "a = all users, u = display user/owner, x = include processes without terminal"),
        "-aux": ("All Processes BSD", "a = all users, u = display user/owner, x = include processes without terminal"),
        "-ef": ("All Processes System V", "-e = select all processes, -f = full-format listing"),
        "-a": ("All Users", "Select all processes except session leaders and processes not associated with terminal"),
        "-u": ("User-Oriented", "Display user-oriented format with CPU/memory stats"),
        "-x": ("Include Daemon Processes", "Include processes that do not have an attached controlling terminal"),
    },
    "grep": {
        "-i": ("Ignore Case", "Case-insensitive matching"),
        "-r": ("Recursive", "Recursively search subdirectories"),
        "-R": ("Recursive Follow Symlinks", "Recursively search directories and follow symlinks"),
        "-v": ("Invert Match", "Select non-matching lines"),
        "-n": ("Line Number", "Prefix each line of output with 1-based line number"),
        "-l": ("Files with Matches", "Print only names of files with matching lines"),
        "-E": ("Extended Regex", "Interpret pattern as extended regular expression (like egrep)"),
        "-o": ("Only Matching", "Print only the matched parts of matching line"),
        "-C": ("Context", "Print num lines of leading and trailing context"),
    },
    "xargs": {
        "-I": ("Replace String", "Replace occurrences of placeholder string with input items"),
        "-0": ("Null Delimited", "Input items are terminated by a null character (pairs with find -print0)"),
        "-n": ("Max Arguments", "Use at most max-args arguments per command line"),
        "-P": ("Parallel Execution", "Run up to max-procs processes concurrently"),
    },
    "lsof": {
        "-i": ("Internet Connections", "Select listening or connected network sockets (e.g. -i :8080)"),
        "-P": ("Port Numbers", "Inhibits conversion of port numbers to port names"),
        "-n": ("No DNS", "Inhibits conversion of network numbers to host names"),
    },
}

TAR_FLAGS = {"x", "c", "v", "z", "j", "J", "f", "p", "t", "C"}


def _command_basename(token: str) -> str:
    """Extract command name ignoring paths (e.g. /usr/bin/find -> find, \\find -> find)."""
    cleaned = token.lstrip("\\")
    return cleaned.split("/")[-1]


def explain_local_command(command: str) -> List[FlagInfo]:
    """Inspect shell command and extract known flags using offline database and unwrapping wrappers."""
    results: List[FlagInfo] = []
    clean_cmd = command.strip()

    try:
        lexer = shlex.shlex(clean_cmd, posix=True, punctuation_chars=True)
        segments: List[List[str]] = []
        current: List[str] = []
        while True:
            tok = lexer.get_token()
            if not tok:
                if current:
                    segments.append(current)
                break
            if tok in (";", "&&", "||", "|", "&", "\n"):
                if current:
                    segments.append(current)
                    current = []
            else:
                current.append(tok)
    except Exception:
        segments = [clean_cmd.split()]

    for segment in segments:
        if not segment:
            continue

        raw_cmd = segment[0]
        args = segment[1:]
        current_cmd, remaining_args, _ = unwrap_command(raw_cmd, args)
        cmd_db = CRYPTIC_FLAG_DATABASE.get(current_cmd, {})
        if not cmd_db:
            continue

        first_arg = True
        for token in remaining_args:
            # Handle dash-less tar flags: e.g. `tar xzvf archive.tar.gz`
            if current_cmd == "tar" and first_arg and not token.startswith("-"):
                first_arg = False
                if all(ch in TAR_FLAGS for ch in token):
                    for char in token:
                        single_flag = f"-{char}"
                        if single_flag in cmd_db:
                            name, desc = cmd_db[single_flag]
                            results.append(FlagInfo(flag=f"{current_cmd} {single_flag}", name=name, description=desc))
                    continue

            first_arg = False

            # Direct lookup
            if token in cmd_db:
                name, desc = cmd_db[token]
                results.append(FlagInfo(flag=f"{current_cmd} {token}", name=name, description=desc))
            elif token.startswith("-") and len(token) > 2 and not token.startswith("--"):
                # Handle ps -aux special case or decompose combined flags like -xzvf
                if current_cmd == "ps" and token == "-aux":
                    name, desc = cmd_db["-aux"]
                    results.append(FlagInfo(flag="ps -aux", name=name, description=desc))
                else:
                    for char in token[1:]:
                        single_flag = f"-{char}"
                        if single_flag in cmd_db:
                            name, desc = cmd_db[single_flag]
                            results.append(FlagInfo(flag=f"{current_cmd} {single_flag}", name=name, description=desc))

    return results
