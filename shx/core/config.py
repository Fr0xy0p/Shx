"""Configuration management for shx."""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple
from pydantic import BaseModel, Field

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "shx"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.json"

SUPPORTED_PROVIDERS: Tuple[str, ...] = ("gemini", "openai", "groq", "ollama")

DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4o-mini",
    "groq": "qwen/qwen3.8-27b",
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
        }
        env_var = env_map.get(target)
        if env_var and os.getenv(env_var):
            return os.getenv(env_var)

        # 2. Config file storage
        return self.api_keys.get(target)

    def get_model(self, provider: Optional[str] = None) -> str:
        target = (provider or self.default_provider).lower()
        return self.models.get(target, DEFAULT_MODELS.get(target, "gpt-4o-mini"))


def get_default_config_path() -> Path:
    """Return default config path, honoring SHX_CONFIG_PATH environment variable override."""
    env_override = os.environ.get("SHX_CONFIG_PATH")
    if env_override:
        return Path(env_override)
    return DEFAULT_CONFIG_PATH


def load_config(config_path: Optional[Path] = None) -> ShxConfig:
    """Load configuration from disk, creating defaults if not present and backing up corrupted files."""
    path = config_path or get_default_config_path()
    if not path.exists():
        return ShxConfig()
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        return ShxConfig(**data)
    except Exception as e:
        bak_path = path.with_name(path.name + ".bak")
        try:
            shutil.copyfile(path, bak_path)
            if os.name == "posix":
                os.chmod(bak_path, 0o600)
        except Exception:
            pass
        print(
            f"Warning: Corrupt configuration file at '{path}' ({e}). "
            f"Backed up to '{bak_path}'. Falling back to defaults.",
            file=sys.stderr,
        )
        return ShxConfig()


def save_config(config: ShxConfig, config_path: Optional[Path] = None) -> None:
    """Atomically save configuration to disk with secure 0600 file permissions and 0700 dir permissions."""
    path = config_path or get_default_config_path()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    content = config.model_dump_json(indent=2)
    # Write to temp file in same directory and atomically replace
    with tempfile.NamedTemporaryFile("w", dir=parent, delete=False, encoding="utf-8") as tf:
        tf.write(content)
        temp_name = tf.name

    if os.name == "posix":
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass

    os.replace(temp_name, path)
    if os.name == "posix":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
