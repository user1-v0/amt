"""Follow a literal ciphertext to a literal key in the same method. Nothing is executed."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path

from tools.stage1 import _describe, _kind, _mostly_text

_METHOD = re.compile(r"(?m)^(?:[\w.\[\]<>, ?]+\s+)?[\w.$]+\([^;]*\)\s*\{")
_B64_CALL = re.compile(r"Base64\.decode|decodeBase64", re.IGNORECASE)
_CIPHER_CALL = re.compile(r"Cipher\.getInstance")
_XOR_KEY = re.compile(r"\^=\s*(0x[0-9a-fA-F]+|\d+)\b")
_STRING = re.compile(r'"([^"\\]{16,})"')
_BYTE_ARRAY = re.compile(r"new byte\[\]\s*\{([^{}]{1,8000})\}")
_NUMBER = re.compile(r"-?0x[0-9a-fA-F]+|-?\d+")
_MAX_BLOB = 64 * 1024
_MAX_HITS = 8
_MAX_FILES = 40
_ROOTS = ("dex", "stage1/src", "ondemand")


@dataclass
class CryptoHit:
    path: str
    via: str
    kind: str
    size: int
    detail: str
    quote: str


def trace_case(case_dir: Path) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    seen: set[tuple[str, str, int]] = set()
    for relative in _source_files(case_dir):
        text = (case_dir / relative).read_text(encoding="utf-8", errors="replace")
        for hit in trace_source(relative, text):
            key = (hit.path, hit.via, hit.size)
            if key in seen:
                continue
            seen.add(key)
            hits.append(hit)
            if len(hits) >= _MAX_HITS:
                return hits
    return hits


def trace_source(path: str, text: str) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for chunk in _methods(text):
        recovered = _recover(chunk)
        if recovered is not None:
            kind, body, via = recovered
            quote = _quote(chunk)
            hits.append(
                CryptoHit(
                    path=path,
                    via=via,
                    kind=kind,
                    size=len(body),
                    detail=_describe(kind, body).strip(),
                    quote=quote,
                )
            )
            continue
        if _CIPHER_CALL.search(chunk) and not _static_material(chunk):
            hits.append(
                CryptoHit(
                    path=path,
                    via="cipher",
                    kind="",
                    size=0,
                    detail="a cipher call has no static ciphertext and key in this method",
                    quote=_quote(chunk),
                )
            )
    return hits


def render_crypto_report(hits: list[CryptoHit]) -> str:
    lines = ["static crypto trace. only a literal ciphertext and a literal key in the same method are decoded."]
    for hit in hits:
        if hit.kind:
            lines.append(f"{hit.path} via={hit.via} kind={hit.kind} size={hit.size}")
            if hit.detail:
                lines.append(hit.detail)
        else:
            lines.append(f"{hit.path} via={hit.via} {hit.detail}")
        if hit.quote:
            lines.append(f"  source: {hit.quote}")
    return "\n".join(lines).strip() + "\n"


def _source_files(case_dir: Path) -> list[str]:
    found: list[str] = []
    for root in _ROOTS:
        directory = case_dir / root
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.suffix.lower() not in {".java", ".smali"} or not path.is_file():
                continue
            found.append(path.relative_to(case_dir).as_posix())
            if len(found) >= _MAX_FILES:
                return found
    return found


def _methods(text: str) -> list[str]:
    starts = [match.start() for match in _METHOD.finditer(text)]
    if not starts:
        return [text[:8000]] if (_B64_CALL.search(text) or _XOR_KEY.search(text) or _CIPHER_CALL.search(text)) else []
    chunks: list[str] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else min(len(text), start + 6000)
        chunk = text[start:end]
        if _B64_CALL.search(chunk) or _XOR_KEY.search(chunk) or _CIPHER_CALL.search(chunk):
            chunks.append(chunk)
    return chunks


def _static_material(chunk: str) -> bool:
    return bool(_STRING.search(chunk) or _BYTE_ARRAY.search(chunk))


def _recover(chunk: str) -> tuple[str, bytes, str] | None:
    key = _xor_key(chunk)
    key_bytes = _key_bytes(chunk)
    for literal in _STRING.findall(chunk)[:8]:
        raw = _b64(literal)
        if raw is None:
            continue
        found = _accept(raw, "base64")
        if found and _B64_CALL.search(chunk):
            return found
        if key is not None and _B64_CALL.search(chunk):
            found = _accept(bytes(byte ^ key for byte in raw), "static-xor")
            if found:
                return found
    for body in _byte_arrays(chunk):
        if key is not None:
            found = _accept(bytes(byte ^ key for byte in body), "static-xor")
            if found:
                return found
        if key_bytes and len(key_bytes) < len(body) and re.search(r"%|key\[", chunk):
            mixed = bytes(byte ^ key_bytes[index % len(key_bytes)] for index, byte in enumerate(body))
            found = _accept(mixed, "static-xor")
            if found:
                return found
    return None


def _accept(data: bytes, via: str) -> tuple[str, bytes, str] | None:
    if not data or len(data) > _MAX_BLOB:
        return None
    kind = _kind(data) or ("text" if _mostly_text(data) else None)
    if kind is None:
        return None
    return kind, data, via


def _b64(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or len(compact) > _MAX_BLOB:
        return None
    try:
        return base64.b64decode(compact, validate=False)
    except (ValueError, binascii.Error):
        return None


def _xor_key(chunk: str) -> int | None:
    match = _XOR_KEY.search(chunk)
    if match is None:
        return None
    value = int(match.group(1), 0)
    if value <= 0 or value > 255:
        return None
    return value


def _key_bytes(chunk: str) -> bytes | None:
    match = re.search(r"(?:key|xorKey)\s*=\s*new byte\[\]\s*\{([^{}]{1,200})\}", chunk)
    if match is None:
        return None
    values = _numbers(match.group(1))
    if not values or len(values) > 32:
        return None
    return bytes(value & 0xFF for value in values)


def _byte_arrays(chunk: str) -> list[bytes]:
    arrays: list[bytes] = []
    for body in _BYTE_ARRAY.findall(chunk):
        values = _numbers(body)
        if len(values) < 4 or len(values) > _MAX_BLOB:
            continue
        arrays.append(bytes(value & 0xFF for value in values))
    return arrays[:4]


def _numbers(body: str) -> list[int]:
    values: list[int] = []
    for token in _NUMBER.findall(body):
        try:
            values.append(int(token, 0))
        except ValueError:
            continue
    return values


def _quote(chunk: str) -> str:
    for pattern in (_B64_CALL, _XOR_KEY, _CIPHER_CALL):
        match = pattern.search(chunk)
        if match:
            start = chunk.rfind("\n", 0, match.start()) + 1
            end = chunk.find("\n", match.end())
            line = chunk[start:] if end < 0 else chunk[start:end]
            return " ".join(line.split())[:240]
    return ""
