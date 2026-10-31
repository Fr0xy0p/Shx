"""AST analyzer using bashlex to inspect shell command structures."""

import re
import shlex
from typing import List, Dict, Any, Optional, Tuple
import bashlex

SUDO_VALUED_OPTS = {"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D", "-R", "-T"}
ENV_VALUED_OPTS = {"-u", "--unset"}
XARGS_VALUED_OPTS = {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs"}
TIMEOUT_VALUED_OPTS = {"-k", "--kill-after", "-s", "--signal"}
STDBUF_VALUED_OPTS = {"-i", "-o", "-e", "--input", "--output", "--error"}
NICE_VALUED_OPTS = {"-n", "--adjustment"}
IONICE_VALUED_OPTS = {"-c", "-n", "-p"}
SHELL_INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "ksh",
    "python", "python3", "perl", "ruby", "node", "php"
}


def normalize_cmd_name(cmd: str) -> str:
    """Normalize command path and leading backslashes (e.g. /bin/rm -> rm, \\rm -> rm)."""
    cleaned = cmd.lstrip("\\")
    return cleaned.split("/")[-1]


def unwrap_command(cmd: str, args: List[str], max_depth: int = 5) -> Tuple[str, List[str], List[str]]:
    """Unwrap wrapper commands (sudo, env, nohup, timeout, xargs, etc.) to discover the core command."""
    wrappers: List[str] = []
    current_cmd = normalize_cmd_name(cmd)
    current_args = list(args)

    for _ in range(max_depth):
        if current_cmd in ("sudo", "doas"):
            wrappers.append(current_cmd)
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in SUDO_VALUED_OPTS:
                    idx += 2
                elif any(arg.startswith(opt) for opt in SUDO_VALUED_OPTS if len(opt) == 2):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "env":
            wrappers.append("env")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in ENV_VALUED_OPTS:
                    idx += 2
                elif any(arg.startswith(opt + "=") for opt in ENV_VALUED_OPTS):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", arg):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "timeout":
            wrappers.append("timeout")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in TIMEOUT_VALUED_OPTS:
                    idx += 2
                elif any(arg.startswith(opt + "=") for opt in TIMEOUT_VALUED_OPTS):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args) and re.match(r"^\d+(?:\.\d+)?[smhd]?$", current_args[idx]):
                idx += 1
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd in ("nohup", "time", "command", "builtin", "exec", "setsid"):
            wrappers.append(current_cmd)
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "nice":
            wrappers.append("nice")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in NICE_VALUED_OPTS:
                    idx += 2
                elif arg.startswith("-n") or arg.startswith("--adjustment="):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "ionice":
            wrappers.append("ionice")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in IONICE_VALUED_OPTS:
                    idx += 2
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "stdbuf":
            wrappers.append("stdbuf")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in STDBUF_VALUED_OPTS:
                    idx += 2
                elif any(arg.startswith(opt + "=") for opt in STDBUF_VALUED_OPTS):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break

        elif current_cmd == "xargs":
            wrappers.append("xargs")
            idx = 0
            while idx < len(current_args):
                arg = current_args[idx]
                if arg == "--":
                    idx += 1
                    break
                if arg in XARGS_VALUED_OPTS:
                    idx += 2
                elif any(arg.startswith(opt + "=") for opt in XARGS_VALUED_OPTS):
                    idx += 1
                elif arg.startswith("-"):
                    idx += 1
                else:
                    break
            if idx < len(current_args):
                current_cmd = normalize_cmd_name(current_args[idx])
                current_args = current_args[idx + 1:]
            else:
                break
        else:
            break

    return current_cmd, current_args, wrappers


class ASTCommandInvocation:
    """Represents a discrete command call extracted from the AST."""
    def __init__(self, command: str, args: List[str], pos: tuple = (0, 0)):
        self.command = command
        self.args = args
        self.pos = pos

    def __repr__(self) -> str:
        return f"ASTCommand(command='{self.command}', args={self.args})"


class ASTAnalysisResult:
    def __init__(self, ast_parsed: bool = True, raw_error: Optional[str] = None):
        self.commands: List[ASTCommandInvocation] = []
        self.redirects: List[Dict[str, str]] = []
        self.piped_commands: List[List[str]] = []
        self.has_pipe_to_shell: bool = False
        self.has_subshell: bool = False
        self.has_eval: bool = False
        self.is_fork_bomb: bool = False
        self.ast_parsed: bool = ast_parsed
        self.raw_error: Optional[str] = raw_error


class CommandASTVisitor:
    """Visits bashlex AST nodes to extract command signatures and dangerous structures."""

    def __init__(self):
        self.result = ASTAnalysisResult()
        self.visited = set()

    def visit(self, node: Any):
        if node is None:
            return

        node_id = id(node)
        if node_id in self.visited:
            return
        self.visited.add(node_id)

        node_kind = getattr(node, "kind", None)

        if node_kind == "command":
            self._handle_command(node)
        elif node_kind == "pipeline":
            self._handle_pipeline(node)
        elif node_kind == "redirect":
            self._handle_redirect(node)
        elif node_kind == "compound":
            self._handle_compound(node)
        elif node_kind in ("commandsubstitution", "processsubstitution", "subshell"):
            self.result.has_subshell = True
            # Check for remote download execution like <(curl ...) or $(curl ...)
            self._check_substitution_remote_exec(node)
        elif node_kind == "function":
            self._check_function_node(node)

        # Generic recursive traversal across all node attributes containing children
        for attr in ("parts", "list", "command", "body", "output", "pattern", "value"):
            child = getattr(node, attr, None)
            if isinstance(child, list):
                for item in child:
                    self.visit(item)
            elif child is not None and hasattr(child, "kind"):
                self.visit(child)

    def _handle_command(self, node: Any):
        words = []
        for part in getattr(node, "parts", []):
            if getattr(part, "kind", "") == "word":
                words.append(part.word)

        if words:
            cmd = words[0]
            args = words[1:]
            self.result.commands.append(ASTCommandInvocation(cmd, args, getattr(node, "pos", (0, 0))))

            unwrapped, _, wrappers = unwrap_command(cmd, args)
            if unwrapped in ("eval", "exec") or "exec" in wrappers:
                self.result.has_eval = True

            # Detect remote exec patterns like: bash -c "$(curl ...)" or bash <(curl ...)
            if unwrapped in SHELL_INTERPRETERS or unwrapped in ("source", "."):
                raw_node_str = " ".join(words)
                if re.search(r"<\(\s*(?:curl|wget|fetch)\b", raw_node_str) or re.search(r"\$\(\s*(?:curl|wget|fetch)\b", raw_node_str):
                    self.result.has_pipe_to_shell = True

    def _check_substitution_remote_exec(self, node: Any):
        cmd_node = getattr(node, "command", None)
        if cmd_node:
            words = [p.word for p in getattr(cmd_node, "parts", []) if getattr(p, "kind", "") == "word"]
            if words:
                inner_cmd, _, _ = unwrap_command(words[0], words[1:])
                if inner_cmd in ("curl", "wget", "fetch"):
                    self.result.has_pipe_to_shell = True

    def _handle_pipeline(self, node: Any):
        pipe_cmds: List[str] = []
        for part in getattr(node, "parts", []):
            if getattr(part, "kind", "") == "command":
                parts = getattr(part, "parts", [])
                cmd_words = [p.word for p in parts if getattr(p, "kind", "") == "word"]
                if cmd_words:
                    unwrapped, _, _ = unwrap_command(cmd_words[0], cmd_words[1:])
                    pipe_cmds.append(unwrapped)

        if pipe_cmds:
            self.result.piped_commands.append(pipe_cmds)
            if len(pipe_cmds) > 1:
                last_cmd = pipe_cmds[-1]
                if last_cmd in SHELL_INTERPRETERS:
                    self.result.has_pipe_to_shell = True

    def _handle_redirect(self, node: Any):
        rtype = getattr(node, "type", ">")
        target_word = ""
        output_node = getattr(node, "output", None)
        if output_node and hasattr(output_node, "word"):
            target_word = output_node.word
        self.result.redirects.append({"type": rtype, "target": target_word})

    def _handle_compound(self, node: Any):
        lst = getattr(node, "list", [])
        if lst and getattr(lst[0], "kind", "") == "reservedword" and getattr(lst[0], "word", "") == "(":
            self.result.has_subshell = True

    def _check_function_node(self, node: Any):
        name_node = getattr(node, "name", None)
        fname = getattr(name_node, "word", "") if name_node else ""
        if not fname:
            return

        body = getattr(node, "body", None)
        if not body:
            return

        stack = [body]
        while stack:
            curr = stack.pop()
            if getattr(curr, "kind", None) == "pipeline":
                cmds = []
                for part in getattr(curr, "parts", []):
                    if getattr(part, "kind", None) == "command":
                        words = [p.word for p in getattr(part, "parts", []) if getattr(p, "kind", None) == "word"]
                        if words:
                            cmds.append(words[0])
                if cmds.count(fname) >= 2:
                    self.result.is_fork_bomb = True
                    return
            for attr in ("parts", "list", "command", "body"):
                child = getattr(curr, attr, None)
                if isinstance(child, list):
                    stack.extend(child)
                elif child is not None:
                    stack.append(child)


def parse_command_ast(command_str: str) -> ASTAnalysisResult:
    """Parse bash/zsh command using bashlex with resilient fallback to shlex."""
    clean_cmd = command_str.strip()
    visitor = CommandASTVisitor()

    # Generic fork bomb regex with backreference supporting arbitrary function names
    fork_bomb_pattern = r"(?P<fname>[a-zA-Z0-9_:.]+)\s*\(\s*\)\s*\{\s*(?P=fname)\s*\|\s*(?P=fname)\s*&\s*(?:;\s*)?\}\s*;\s*(?P=fname)"
    if re.search(fork_bomb_pattern, clean_cmd):
        visitor.result.is_fork_bomb = True

    try:
        nodes = bashlex.parse(clean_cmd)
        for node in nodes:
            visitor.visit(node)
        visitor.result.ast_parsed = True
        return visitor.result
    except Exception as e:
        # Start fresh on parse failure to prevent partial duplicate states
        fallback_result = ASTAnalysisResult(ast_parsed=False, raw_error=str(e))
        if visitor.result.is_fork_bomb:
            fallback_result.is_fork_bomb = True

        try:
            lexer = shlex.shlex(clean_cmd, posix=True, punctuation_chars=True)
            current_segment: List[str] = []
            while True:
                token = lexer.get_token()
                if not token:
                    if current_segment:
                        _register_fallback_segment(fallback_result, current_segment)
                    break
                if token in (";", "&&", "||", "|", "&", "\n"):
                    if current_segment:
                        _register_fallback_segment(fallback_result, current_segment)
                        current_segment = []
                elif token in (">", ">>", ">|", "&>", "&>>"):
                    target = lexer.get_token()
                    if target:
                        fallback_result.redirects.append({"type": token, "target": target})
                elif token == ">&":
                    # fd redirection like 2>&1, not a file write
                    lexer.get_token()
                else:
                    current_segment.append(token)
        except Exception:
            # Fallback simple split if shlex fails on quotes
            words = clean_cmd.split()
            if words:
                _register_fallback_segment(fallback_result, words)

        # Regex fallback for pipe-to-shell or remote execution
        pipe_shell_pattern = (
            r"\|\s*(?:(?:sudo|env|nohup)\s+)*(?:/[\w.-]+/)*"
            r"(?:bash|sh|zsh|dash|ksh|python|python3|perl|ruby|node|php)\b"
        )
        if re.search(pipe_shell_pattern, clean_cmd):
            fallback_result.has_pipe_to_shell = True

        remote_exec_pattern = (
            r"(?:bash|sh|zsh|dash|ksh|source|\.)\s+.*?<\(\s*(?:curl|wget|fetch)\b|"
            r"(?:bash|sh|zsh|dash|ksh)\s+(?:-[a-zA-Z]*c[a-zA-Z]*\s+).*?\$\(\s*(?:curl|wget|fetch)\b"
        )
        if re.search(remote_exec_pattern, clean_cmd):
            fallback_result.has_pipe_to_shell = True

        return fallback_result


def _register_fallback_segment(result: ASTAnalysisResult, segment: List[str]) -> None:
    # Skip leading VAR=val assignments
    idx = 0
    while idx < len(segment) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", segment[idx]):
        idx += 1
    if idx < len(segment):
        cmd = segment[idx]
        args = segment[idx + 1:]
        result.commands.append(ASTCommandInvocation(cmd, args))
        unwrapped, _, _ = unwrap_command(cmd, args)
        if unwrapped in ("eval", "exec"):
            result.has_eval = True
