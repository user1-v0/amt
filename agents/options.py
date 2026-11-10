"""Shared Claude Agent SDK options for the three analysis sessions."""

from __future__ import annotations

import json
import os
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from tools.mcp_server import ALLOWED_TOOLS

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def session_options(
    *,
    system: str,
    schema: dict,
    max_turns: int,
    cwd: Path | None = None,
    server=None,
) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        model=os.environ.get("CLAUDE_MODEL", "sonnet"),
        system_prompt=system,
        setting_sources=[],
        permission_mode="dontAsk",
        tools=[],
        allowed_tools=list(ALLOWED_TOOLS) if server is not None else [],
        mcp_servers={"case": server} if server is not None else {},
        strict_mcp_config=True,
        output_format={"type": "json_schema", "schema": schema},
        max_turns=max_turns,
        cwd=str(cwd) if cwd is not None else None,
    )


def extract_json(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("agent result did not contain a JSON object")
    parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("agent result JSON was not an object")
    return parsed


async def run_structured(prompt: str, options: ClaudeAgentOptions) -> dict:
    result: ResultMessage | None = None
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, ResultMessage):
            result = message
    if result is None:
        raise RuntimeError("agent returned no result")
    if result.is_error:
        detail = result.result or ", ".join(result.errors or []) or "agent error"
        raise RuntimeError(detail)
    payload = result.structured_output
    if isinstance(payload, str):
        return extract_json(payload)
    if isinstance(payload, dict):
        return payload
    if result.result:
        return extract_json(result.result)
    raise RuntimeError("agent returned empty output")
