"""Unified multi-provider LLM client supporting Gemini, OpenAI, Groq, and Ollama."""

import json
import os
import re
from typing import Dict, Any, Generator, Optional, List
from pydantic import BaseModel, Field

from shx.core.config import ShxConfig, load_config
from shx.llm.prompts import build_translation_prompt, SYSTEM_EXPLAINER_PROMPT


class FlagExplanation(BaseModel):
    flag: str
    description: str


class CommandSuggestion(BaseModel):
    command: str
    summary: str
    flags_breakdown: List[FlagExplanation] = Field(default_factory=list)
    notes: Optional[str] = ""
    raw_response: Optional[str] = None


class LLMError(Exception):
    """Custom exception for LLM provider errors."""
    pass


class LLMClient:
    """Dispatches requests to Gemini, OpenAI, Groq, or Ollama."""

    def __init__(self, config: Optional[ShxConfig] = None):
        self.config = config or load_config()

    def translate(self, query: str, context: Dict[str, Any]) -> CommandSuggestion:
        """Translate natural language query into verified shell command JSON."""
        sys_prompt, user_msg = build_translation_prompt(query, context)
        provider = self.config.default_provider.lower()

        raw_text = self._generate_completion(provider, sys_prompt, user_msg)
        return self._parse_suggestion_json(raw_text)

    def explain(self, command_or_output: str, is_error: bool = False) -> str:
        """Generate deep explanation of cryptic command flags or command output."""
        provider = self.config.default_provider.lower()
        if is_error:
            user_msg = f"Please explain this terminal error output and provide a solution:\n```\n{command_or_output}\n```"
        else:
            user_msg = f"Please explain this shell command in detail:\n```bash\n{command_or_output}\n```"

        return self._generate_completion(provider, SYSTEM_EXPLAINER_PROMPT, user_msg)

    def stream_explanation(self, command_or_output: str, is_error: bool = False) -> Generator[str, None, None]:
        """Stream explanation chunks."""
        provider = self.config.default_provider.lower()
        if is_error:
            user_msg = f"Please explain this terminal error output and provide a solution:\n```\n{command_or_output}\n```"
        else:
            user_msg = f"Please explain this shell command in detail:\n```bash\n{command_or_output}\n```"

        yield from self._stream_completion(provider, SYSTEM_EXPLAINER_PROMPT, user_msg)

    def _generate_completion(self, provider: str, system_prompt: str, user_prompt: str) -> str:
        """Direct completion generation dispatch."""
        if provider == "gemini":
            return self._call_gemini(system_prompt, user_prompt)
        elif provider in ("openai", "groq", "ollama"):
            return self._call_openai_compatible(provider, system_prompt, user_prompt)
        else:
            raise LLMError(f"Unsupported provider: '{provider}'. Supported: gemini, openai, groq, ollama.")

    def _stream_completion(self, provider: str, system_prompt: str, user_prompt: str) -> Generator[str, None, None]:
        """Streaming completion dispatch."""
        if provider == "gemini":
            yield from self._stream_gemini(system_prompt, user_prompt)
        elif provider in ("openai", "groq", "ollama"):
            yield from self._stream_openai_compatible(provider, system_prompt, user_prompt)
        else:
            raise LLMError(f"Unsupported provider: '{provider}'.")

    # ---- Google Gemini Provider ----
    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        api_key = self.config.get_api_key("gemini")
        if not api_key:
            raise LLMError(
                "Gemini API key not found.\n"
                "Set it via `export GEMINI_API_KEY='your-key'` or configure using `shx config`."
            )
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            model_name = self.config.get_model("gemini")
            response = client.models.generate_content(
                model=model_name,
                contents=user_prompt,
                config={"system_instruction": system_prompt},
            )
            return response.text or ""
        except Exception as e:
            raise LLMError(f"Gemini API error: {str(e)}")

    def _stream_gemini(self, system_prompt: str, user_prompt: str) -> Generator[str, None, None]:
        api_key = self.config.get_api_key("gemini")
        if not api_key:
            raise LLMError("Gemini API key not found. Set GEMINI_API_KEY or run `shx config`.")
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            model_name = self.config.get_model("gemini")
            response_stream = client.models.generate_content_stream(
                model=model_name,
                contents=user_prompt,
                config={"system_instruction": system_prompt},
            )
            for chunk in response_stream:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            raise LLMError(f"Gemini stream error: {str(e)}")

    # ---- OpenAI / Groq / Ollama Provider ----
    def _get_openai_client(self, provider: str):
        from openai import OpenAI
        model = self.config.get_model(provider)

        if provider == "ollama":
            base_url = self.config.ollama_base_url
            return OpenAI(base_url=base_url, api_key="ollama"), model

        api_key = self.config.get_api_key(provider)
        if not api_key:
            env_name = f"{provider.upper()}_API_KEY"
            raise LLMError(
                f"{provider.capitalize()} API key not found.\n"
                f"Set it via `export {env_name}='your-key'` or run `shx config`."
            )

        if provider == "groq":
            return OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key), model

        return OpenAI(api_key=api_key), model

    def _call_openai_compatible(self, provider: str, system_prompt: str, user_prompt: str) -> str:
        try:
            client, model = self._get_openai_client(provider)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            raise LLMError(f"{provider.capitalize()} API error: {str(e)}")

    def _stream_openai_compatible(self, provider: str, system_prompt: str, user_prompt: str) -> Generator[str, None, None]:
        try:
            client, model = self._get_openai_client(provider)
            response_stream = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                stream=True,
            )
            for chunk in response_stream:
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    yield delta.content
        except Exception as e:
            raise LLMError(f"{provider.capitalize()} stream error: {str(e)}")

    # ---- JSON Extraction ----
    def _parse_suggestion_json(self, raw_text: str) -> CommandSuggestion:
        """Extract and validate JSON response."""
        cleaned = raw_text.strip()
        # Remove Markdown code fences if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            cleaned = cleaned.strip()

        # Find first '{' and last '}'
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1:
            cleaned = cleaned[start : end + 1]

        try:
            data = json.loads(cleaned)
            breakdown = [
                FlagExplanation(flag=item.get("flag", ""), description=item.get("description", ""))
                for item in data.get("flags_breakdown", [])
            ]
            return CommandSuggestion(
                command=data.get("command", "").strip(),
                summary=data.get("summary", ""),
                flags_breakdown=breakdown,
                notes=data.get("notes", ""),
                raw_response=raw_text,
            )
        except Exception:
            # Fallback parsing: if model returned command as raw text
            first_line = raw_text.strip().split("\n")[0]
            first_line = re.sub(r"^`+|`+$", "", first_line).strip()
            return CommandSuggestion(
                command=first_line,
                summary="Synthesized shell command",
                flags_breakdown=[],
                raw_response=raw_text,
            )
