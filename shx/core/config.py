"""Configuration management for shx."""

import json
import os
from pathlib import Path
from typing import Dict, Optional
from pydantic import BaseModel, Field

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "shx"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.json"

DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4o-mini",
    "groq": "llama-3.3-70b-versatile",
    "ollama": "llama3.2",
}


class ShxConfig(BaseModel):
    default_provider: str = Field(default="gemini", description="Active LLM provider: gemini, openai, groq, ollama")
    api_keys: Dict[str, str] = Field(default_factory=dict, description="Saved API keys per provider")
    models: Dict[str, str] = Field(default_factory=lambda: DEFAULT_MODELS.copy(), description="Model names per provider")
    ollama_base_url: str = Field(default="http://localhost:11434/v1", description="Base URL for Ollama / local endpoint")
    require_confirmation: bool = Field(default=True, description="Always prompt before executing a command")
    auto_copy_clipboard: bool = Field(default=False, description="Automatically copy generated command to clipboard")
    strict_safety: bool = Field(default=True, description="Strict AST guardrails preventing dangerous execution")

    def get_api_key(self, provider: Optional[str] = None) -> Optional[str]:
        target = (provider or self.default_provider).lower()
        # 1. Environment variable priority
        env_map = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "groq": "GROQ_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }
        env_var = env_map.get(target)
        if env_var and os.getenv(env_var):
            return os.getenv(env_var)
        
        # 2. Config file storage
        return self.api_keys.get(target)

    def get_model(self, provider: Optional[str] = None) -> str:
        target = (provider or self.default_provider).lower()
        return self.models.get(target, DEFAULT_MODELS.get(target, "gpt-4o-mini"))


def load_config(config_path: Path = DEFAULT_CONFIG_PATH) -> ShxConfig:
    """Load configuration from disk, creating defaults if not present."""
    if not config_path.exists():
        return ShxConfig()
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        return ShxConfig(**data)
    except Exception:
        return ShxConfig()


def save_config(config: ShxConfig, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Save configuration to disk."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config.model_dump_json(indent=2), encoding="utf-8")
