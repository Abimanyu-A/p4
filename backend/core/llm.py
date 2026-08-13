"""Shared Gemini client for the Validate and Prove stages.

Uses Google Gemini (free-tier friendly) instead of the Anthropic API. Reads
GEMINI_API_KEY from the environment or a local .env file in the repo root.
"""

from __future__ import annotations

import functools
import json
import os
import re
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

# gemini-flash-lite-latest has a materially higher free-tier RPM quota than
# gemini-flash-latest, which matters here since Validate/Prove fire one call
# per finding.
MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
MAX_RETRIES = 5


@functools.lru_cache(maxsize=1)
def get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Get a free key at "
            "https://aistudio.google.com/apikey and put it in a .env file "
            "(GEMINI_API_KEY=...) at the project root, or export it."
        )
    return genai.Client(api_key=api_key)


def _retry_delay_seconds(exc: genai_errors.ClientError, attempt: int) -> float:
    match = re.search(r"retry in ([\d.]+)s", str(exc))
    if match:
        return float(match.group(1)) + 1.0
    return min(2**attempt, 30)


def structured_call(system_prompt: str, user_prompt: str, schema: dict) -> dict:
    """Call Gemini and return a dict parsed from a JSON response constrained
    to the given (JSON-Schema-shaped) schema. Retries on rate limits."""
    client = get_client()
    for attempt in range(MAX_RETRIES):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    response_schema=schema,
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except genai_errors.ClientError as exc:
            if exc.code == 429 and attempt < MAX_RETRIES - 1:
                time.sleep(_retry_delay_seconds(exc, attempt))
                continue
            raise
    raise RuntimeError("unreachable")
