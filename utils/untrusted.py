"""Keep sample text in a fence the sample cannot close."""

from __future__ import annotations

import re

# Bidi overrides and isolates, plus zero-width and byte-order marks.
_HIDDEN = frozenset(
    "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2066\u2067\u2068\u2069\ufeff"
)
_WS = re.compile(r"\s+")


def neutralize(text: str) -> str:
    kept: list[str] = []
    for char in text:
        if char in _HIDDEN:
            continue
        if ord(char) < 32 and char not in "\n\t":
            kept.append(" ")
            continue
        if char == "\x7f":
            kept.append(" ")
            continue
        kept.append(char)
    return "".join(kept)


def collapse_ws(text: str) -> str:
    return _WS.sub(" ", neutralize(text)).strip()


_UNREAD_EXCUSE = re.compile(
    r"did not open|didn't open|did not read|didn't read|could not open|couldn't open|"
    r"could not read|couldn't read|did not check|not sure|unsure",
    re.IGNORECASE,
)


def without_unread_excuse(text: str) -> str:
    """Drop a sentence that blames an unread file or stops at being unsure."""
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    kept = [part.strip() for part in parts if part.strip() and not _UNREAD_EXCUSE.search(part)]
    return " ".join(kept).strip()


def quote_in_text(quote: str, document: str) -> bool:
    needle = collapse_ws(quote)
    if not needle:
        return False
    return needle in collapse_ws(document)


def _break_nonce(nonce: str) -> str:
    if len(nonce) < 2:
        return f"{nonce} "
    middle = len(nonce) // 2
    return f"{nonce[:middle]} {nonce[middle:]}"


def fence(text: str, nonce: str) -> str:
    body = neutralize(text)
    if nonce and nonce in body:
        body = body.replace(nonce, _break_nonce(nonce))
    return f"<<SAMPLE:{nonce}>>\n{body}\n<<END SAMPLE:{nonce}>>"
