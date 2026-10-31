"""Unit tests for configuration loading and persistence."""

import os
import stat
from shx.core.config import (
    ShxConfig,
    load_config,
    save_config,
    SUPPORTED_PROVIDERS,
)


def test_default_config():
    cfg = ShxConfig()
    assert cfg.default_provider == "gemini"
    assert cfg.require_confirmation is True
    assert cfg.strict_safety is True
    assert "anthropic" not in SUPPORTED_PROVIDERS
    assert set(SUPPORTED_PROVIDERS) == {"gemini", "openai", "groq", "ollama"}


def test_api_key_resolution(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    cfg = ShxConfig(api_keys={"gemini": "key-from-config"})

    # Config file key
    assert cfg.get_api_key("gemini") == "key-from-config"

    # Environment variable priority
    monkeypatch.setenv("GEMINI_API_KEY", "env-key-override")
    assert cfg.get_api_key("gemini") == "env-key-override"


def test_save_and_load_config(tmp_path):
    target = tmp_path / "test_config.json"
    cfg = ShxConfig(
        default_provider="openai",
        auto_copy_clipboard=True,
        require_confirmation=False,
        strict_safety=False,
    )
    save_config(cfg, config_path=target)

    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600

    loaded = load_config(config_path=target)
    assert loaded.default_provider == "openai"
    assert loaded.auto_copy_clipboard is True
    assert loaded.require_confirmation is False
    assert loaded.strict_safety is False


def test_corrupt_config_backup(tmp_path, capsys):
    target = tmp_path / "corrupt_config.json"
    target.write_text("{ this is invalid json ; ", encoding="utf-8")

    loaded = load_config(config_path=target)
    assert loaded.default_provider == "gemini"

    bak_path = tmp_path / "corrupt_config.json.bak"
    assert bak_path.exists()
    assert "{ this is invalid json" in bak_path.read_text(encoding="utf-8")

    err = capsys.readouterr().err
    assert "Corrupt configuration file" in err
