"""Unit tests for configuration loading and persistence."""

import os
from pathlib import Path
from shx.core.config import ShxConfig, load_config, save_config


def test_default_config():
    cfg = ShxConfig()
    assert cfg.default_provider == "gemini"
    assert cfg.require_confirmation is True
    assert cfg.strict_safety is True


def test_api_key_resolution(monkeypatch):
    cfg = ShxConfig(api_keys={"gemini": "key-from-config"})

    # Config file key
    assert cfg.get_api_key("gemini") == "key-from-config"

    # Environment variable priority
    monkeypatch.setenv("GEMINI_API_KEY", "env-key-override")
    assert cfg.get_api_key("gemini") == "env-key-override"


def test_save_and_load_config(tmp_path):
    target = tmp_path / "test_config.json"
    cfg = ShxConfig(default_provider="openai", auto_copy_clipboard=True)
    save_config(cfg, config_path=target)

    loaded = load_config(config_path=target)
    assert loaded.default_provider == "openai"
    assert loaded.auto_copy_clipboard is True
