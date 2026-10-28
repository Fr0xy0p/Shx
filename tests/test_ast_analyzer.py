"""Unit tests for shell AST analyzer."""

from shx.core.safety.ast_analyzer import parse_command_ast


def test_simple_command_ast():
    res = parse_command_ast("ls -la /tmp")
    assert len(res.commands) == 1
    assert res.commands[0].command == "ls"
    assert res.commands[0].args == ["-la", "/tmp"]
    assert not res.has_pipe_to_shell
    assert not res.is_fork_bomb


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


def test_fork_bomb_detection():
    res = parse_command_ast(":(){ :|:& };:")
    assert res.is_fork_bomb is True

    res2 = parse_command_ast("bomb(){ bomb|bomb& };bomb")
    assert res2.is_fork_bomb is True


def test_redirect_detection():
    res = parse_command_ast("echo 'data' > /dev/sda")
    assert len(res.redirects) == 1
    assert res.redirects[0]["target"] == "/dev/sda"
