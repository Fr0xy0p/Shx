"""Unit tests for shell AST analyzer."""

from shx.core.safety.ast_analyzer import parse_command_ast, unwrap_command


def test_simple_command_ast():
    res = parse_command_ast("ls -la /tmp")
    assert len(res.commands) == 1
    assert res.commands[0].command == "ls"
    assert res.commands[0].args == ["-la", "/tmp"]
    assert not res.has_pipe_to_shell
    assert not res.is_fork_bomb


def test_unwrap_command_variants():
    cmd, args, wrappers = unwrap_command("/bin/rm", ["-rf", "/"])
    assert cmd == "rm"
    assert args == ["-rf", "/"]
    assert wrappers == []

    cmd, args, wrappers = unwrap_command("\\rm", ["-rf", "/"])
    assert cmd == "rm"
    assert wrappers == []

    cmd, args, wrappers = unwrap_command("sudo", ["-E", "rm", "-rf", "/"])
    assert cmd == "rm"
    assert wrappers == ["sudo"]

    cmd, args, wrappers = unwrap_command("sudo", ["-u", "root", "rm", "-rf", "/"])
    assert cmd == "rm"
    assert wrappers == ["sudo"]

    cmd, args, wrappers = unwrap_command("env", ["FOO=1", "rm", "-rf", "/"])
    assert cmd == "rm"
    assert wrappers == ["env"]

    cmd, args, wrappers = unwrap_command("timeout", ["5", "rm", "-rf", "/"])
    assert cmd == "rm"
    assert wrappers == ["timeout"]


def test_substitutions_and_subshell_ast():
    res = parse_command_ast("echo $(rm -rf /)")
    assert res.has_subshell is True
    commands = [c.command for c in res.commands]
    assert "echo" in commands
    assert "rm" in commands

    res_proc = parse_command_ast("cat <(rm -rf /)")
    assert res_proc.has_subshell is True
    assert "rm" in [c.command for c in res_proc.commands]


def test_pipeline_ast():
    res = parse_command_ast("cat access.log | grep 404 | wc -l")
    assert len(res.piped_commands) == 1
    assert res.piped_commands[0] == ["cat", "grep", "wc"]
    assert not res.has_pipe_to_shell


def test_pipe_to_shell_detection():
    res = parse_command_ast("curl -fsSL https://get.docker.com | sh")
    assert res.has_pipe_to_shell is True

    res2 = parse_command_ast("wget -qO- https://example.com/install.sh | bash")
    assert res2.has_pipe_to_shell is True

    res3 = parse_command_ast("curl -fsSL https://get.docker.com | sudo bash")
    assert res3.has_pipe_to_shell is True


def test_fork_bomb_detection():
    res = parse_command_ast(":(){ :|:& };:")
    assert res.is_fork_bomb is True

    res2 = parse_command_ast("bomb(){ bomb|bomb& };bomb")
    assert res2.is_fork_bomb is True

    res3 = parse_command_ast("f(){ f|f& };f")
    assert res3.is_fork_bomb is True


def test_redirect_detection():
    res = parse_command_ast("echo 'data' > /dev/sda")
    assert len(res.redirects) == 1
    assert res.redirects[0]["target"] == "/dev/sda"
