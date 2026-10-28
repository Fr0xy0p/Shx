"""AST analyzer using bashlex to inspect shell command structures."""

import re
import shlex
from typing import List, Dict, Any, Optional
import bashlex
from bashlex import ast


class ASTCommandInvocation:
    """Represents a discrete command call extracted from the AST."""
    def __init__(self, command: str, args: List[str], pos: tuple = (0, 0)):
        self.command = command
        self.args = args
        self.pos = pos

    def __repr__(self) -> str:
        return f"ASTCommand(command='{self.command}', args={self.args})"


class ASTAnalysisResult:
    def __init__(self):
        self.commands: List[ASTCommandInvocation] = []
        self.redirects: List[Dict[str, str]] = []
        self.piped_commands: List[List[str]] = []
        self.has_pipe_to_shell: bool = False
        self.has_subshell: bool = False
        self.has_eval: bool = False
        self.is_fork_bomb: bool = False
        self.raw_error: Optional[str] = None


class CommandASTVisitor:
    """Visits bashlex AST nodes to extract command signatures and dangerous structures."""

    def __init__(self):
        self.result = ASTAnalysisResult()

    def visit(self, node: Any):
        if node is None:
            return

        node_kind = getattr(node, "kind", None)

        if node_kind == "command":
            self._handle_command(node)
        elif node_kind == "pipeline":
            self._handle_pipeline(node)
        elif node_kind == "redirect":
            self._handle_redirect(node)
        elif node_kind == "subshell":
            self.result.has_subshell = True
        elif node_kind == "function":
            # Function definitions (checked for fork bomb patterns)
            self._check_function_node(node)

        # Recursively visit children
        parts = getattr(node, "parts", None)
        if isinstance(parts, list):
            for part in parts:
                self.visit(part)

        # Handle list/compound nodes
        list_nodes = getattr(node, "list", None)
        if isinstance(list_nodes, list):
            for item in list_nodes:
                self.visit(item)

    def _handle_command(self, node: Any):
        words = []
        for part in getattr(node, "parts", []):
            if getattr(part, "kind", "") == "word":
                words.append(part.word)

        if words:
            cmd = words[0]
            args = words[1:]
            self.result.commands.append(ASTCommandInvocation(cmd, args, getattr(node, "pos", (0, 0))))
            if cmd in ("eval", "exec"):
                self.result.has_eval = True

    def _handle_pipeline(self, node: Any):
        pipe_cmds = []
        for part in getattr(node, "parts", []):
            if getattr(part, "kind", "") == "command":
                parts = getattr(part, "parts", [])
                cmd_words = [p.word for p in parts if getattr(p, "kind", "") == "word"]
                if cmd_words:
                    pipe_cmds.append(cmd_words[0])

        if pipe_cmds:
            self.result.piped_commands.append(pipe_cmds)
            # Check if piping remote or arbitrary data directly into shell interpreter
            shells = {"bash", "sh", "zsh", "python", "python3", "perl", "ruby"}
            if len(pipe_cmds) > 1 and pipe_cmds[-1] in shells:
                self.result.has_pipe_to_shell = True

    def _handle_redirect(self, node: Any):
        rtype = getattr(node, "type", ">")
        target_word = ""
        output_node = getattr(node, "output", None)
        if output_node and hasattr(output_node, "word"):
            target_word = output_node.word
        self.result.redirects.append({"type": rtype, "target": target_word})

    def _check_function_node(self, node: Any):
        # Look for fork bomb pattern: :(){ :|:& };:
        name = getattr(node, "name", "")
        if name in (":", "_"):
            self.result.is_fork_bomb = True


def parse_command_ast(command_str: str) -> ASTAnalysisResult:
    """Parse bash/zsh command using bashlex with resilient fallback to shlex/regex."""
    clean_cmd = command_str.strip()
    visitor = CommandASTVisitor()

    # Pre-check classic fork bombs that might fail tokenizer
    fork_bomb_pattern = r"(\:\s*\(\s*\)\s*\{|bomb\s*\(\s*\)\s*\{|\:\s*\|\s*\:\s*&\s*\)\s*;\s*\:)"
    if re.search(fork_bomb_pattern, clean_cmd):
        visitor.result.is_fork_bomb = True

    try:
        nodes = bashlex.parse(clean_cmd)
        for node in nodes:
            visitor.visit(node)
        return visitor.result
    except Exception as e:
        # Fallback to tokenizing via shlex if bashlex encounters zsh or complex syntax
        visitor.result.raw_error = str(e)
        try:
            tokens = shlex.split(clean_cmd)
            if tokens:
                visitor.result.commands.append(ASTCommandInvocation(tokens[0], tokens[1:]))
        except Exception:
            # Last-resort word split
            words = clean_cmd.split()
            if words:
                visitor.result.commands.append(ASTCommandInvocation(words[0], words[1:]))

        # Check for pipe to shell via regex in fallback
        if re.search(r"\|\s*(bash|sh|zsh|sudo\s+bash|sudo\s+sh)", clean_cmd):
            visitor.result.has_pipe_to_shell = True

        return visitor.result
