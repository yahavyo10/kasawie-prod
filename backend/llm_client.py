"""
Thin wrapper around Groq's OpenAI-compatible chat completions endpoint.

Reads the API key from the JUBAL_API_KEY environment variable -- never
hardcode it here. Set it in backend/.env (see .env.example) or export it
in your shell before running the server.
"""
import os
import json
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.1-8b-instant and llama-3.3-70b-versatile were deprecated on Groq in
# June 2026 -- don't use those. Fast model for the mostly-mechanical phase-1
# localization call, stronger reasoning model for the phase-2 narrative call.
# Override either via env vars; check https://console.groq.com/docs/models
# for the current lineup if these stop working.
DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
FAST_MODEL = os.environ.get("GROQ_MODEL_FAST", "openai/gpt-oss-20b")


class LLMError(Exception):
    pass


def _api_key() -> str:
    key = os.environ.get("JUBAL_API_KEY")
    if not key:
        raise LLMError(
            "JUBAL_API_KEY is not set. Put it in backend/.env or export it "
            "in your shell before starting the server."
        )
    return key


def call_llm_json(system_prompt: str, user_prompt: str, model: str = None, temperature: float = 0.2) -> dict:
    """Calls Groq's chat completions endpoint and parses the response as JSON.
    Raises LLMError with a readable message on any failure so the pipeline
    can surface it in the UI instead of crashing silently."""
    model = model or DEFAULT_MODEL
    headers = {
        "Authorization": f"Bearer {_api_key()}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }

    try:
        resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=60)
    except requests.RequestException as e:
        raise LLMError(f"Could not reach Groq API: {e}")

    if resp.status_code != 200:
        raise LLMError(f"Groq API returned {resp.status_code}: {resp.text[:500]}")

    data = resp.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise LLMError(f"Unexpected Groq response shape: {data}") from e

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        cleaned = content.strip().strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise LLMError(f"Model did not return valid JSON: {content[:500]}") from e
