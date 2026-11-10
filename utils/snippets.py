"""A short window of decompiled code around a finding quote."""

from __future__ import annotations

from pathlib import Path

from tools.mcp_server import resolve_inside
from utils.untrusted import collapse_ws, neutralize

CONTEXT_LINES = 6
MAX_SNIPPET_CHARS = 6_000


def locate_span(document: str, quote: str) -> tuple[int, int] | None:
    """Return the quote's start and end offsets in the original document."""
    if not quote:
        return None
    exact = document.find(quote)
    if exact >= 0:
        return exact, exact + len(quote)
    needle = collapse_ws(quote)
    if not needle:
        return None
    folded, indexes = _fold(document)
    pos = folded.find(needle)
    if pos < 0:
        return None
    start = indexes[pos]
    end = indexes[pos + len(needle) - 1] + 1
    return start, end


def code_window(document: str, start: int, end: int) -> tuple[str, int, int]:
    """Keep a few lines around the span. Offsets are into the returned text."""
    win_start = _line_start(document, start, CONTEXT_LINES)
    win_end = _line_end(document, end, CONTEXT_LINES)
    snippet = document[win_start:win_end]
    highlight_start = start - win_start
    highlight_end = end - win_start
    if len(snippet) > MAX_SNIPPET_CHARS:
        center = (highlight_start + highlight_end) // 2
        left = max(0, center - MAX_SNIPPET_CHARS // 2)
        right = min(len(snippet), left + MAX_SNIPPET_CHARS)
        snippet = snippet[left:right]
        highlight_start -= left
        highlight_end -= left
    highlight_start = max(0, min(highlight_start, len(snippet)))
    highlight_end = max(highlight_start, min(highlight_end, len(snippet)))
    return snippet, highlight_start, highlight_end


def evidence_snippet(case_dir: Path | None, relative: str, quote: str) -> dict[str, int | str]:
    document = _read_case_file(case_dir, relative)
    if document is None:
        return {"snippet": quote, "highlight_start": 0, "highlight_end": len(quote)}
    span = locate_span(document, quote)
    if span is None:
        return {"snippet": quote, "highlight_start": 0, "highlight_end": len(quote)}
    snippet, start, end = code_window(document, span[0], span[1])
    return {"snippet": snippet, "highlight_start": start, "highlight_end": end}


def _fold(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    indexes: list[int] = []
    pending = False
    started = False
    for index, char in enumerate(neutralize(text)):
        if char.isspace():
            if started:
                pending = True
            continue
        if pending:
            chars.append(" ")
            indexes.append(index)
            pending = False
        chars.append(char)
        indexes.append(index)
        started = True
    return "".join(chars), indexes


def _line_start(document: str, offset: int, lines: int) -> int:
    cursor = document.rfind("\n", 0, offset)
    cursor = 0 if cursor < 0 else cursor + 1
    for _ in range(lines):
        if cursor <= 0:
            return 0
        previous = document.rfind("\n", 0, cursor - 1)
        cursor = 0 if previous < 0 else previous + 1
    return cursor


def _line_end(document: str, offset: int, lines: int) -> int:
    cursor = document.find("\n", offset)
    cursor = len(document) if cursor < 0 else cursor + 1
    for _ in range(lines):
        if cursor >= len(document):
            return len(document)
        nxt = document.find("\n", cursor)
        if nxt < 0:
            return len(document)
        cursor = nxt + 1
    return cursor


def _read_case_file(case_dir: Path | None, relative: str) -> str | None:
    if case_dir is None or not relative:
        return None
    try:
        path = resolve_inside(case_dir, relative)
    except ValueError:
        return None
    if not path.is_file():
        return None
    data = path.read_bytes()
    if b"\x00" in data[:512]:
        return None
    return data.decode("utf-8", errors="replace")
