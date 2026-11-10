"""Subprocess wrappers for the droidasc CLI."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from utils.limits import MAX_CLASS_CHARS, truncate

_THREAD_COMMANDS = {"getclass", "disassemble", "listclass", "findrefs"}


def _with_threads(args: list[str]) -> list[str]:
    """One worker inside droidasc. getmanifest does not accept --threads."""
    if not args or args[0] != "droidasc" or "--threads" in args or len(args) < 2:
        return args
    if args[1] not in _THREAD_COMMANDS:
        return args
    flag = ["--threads", "1"]
    if args[1] == "findrefs" and len(args) >= 3:
        return [args[0], args[1], args[2], *flag, *args[3:]]
    return [*args, *flag]

_CLASS_NAME = re.compile(r"[A-Za-z0-9_$./;]+")
_FIND_KINDS = {"string", "type", "method", "field"}
_TIMEOUT_SECONDS = 180


@dataclass
class ToolResult:
    ok: bool
    text: str
    path: str | None
    error: str | None
    backend: str


def droidasc_available() -> bool:
    return shutil.which("droidasc") is not None


def validate_class_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned or cleaned.startswith("-") or not _CLASS_NAME.fullmatch(cleaned):
        raise ValueError(f"invalid class name: {name!r}")
    return cleaned


def class_filename(class_name: str, suffix: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", class_name).strip("._") or "class"
    return f"{safe}.{suffix}"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    args = _with_threads(args)
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )


def _missing() -> ToolResult:
    return ToolResult(False, "", None, "droidasc not on PATH", "none")


def _failure(proc: subprocess.CompletedProcess[str], fallback: str) -> ToolResult:
    detail = (proc.stderr or proc.stdout or fallback).strip()
    return ToolResult(False, "", None, detail[:2000], "none")


def get_manifest(apk: Path, dest_xml: Path) -> ToolResult:
    if not droidasc_available():
        return _missing()
    dest_xml.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(["droidasc", "getmanifest", str(apk), "-o", str(dest_xml)])
    if proc.returncode != 0:
        return _failure(proc, "droidasc getmanifest failed")
    if dest_xml.is_file():
        text = dest_xml.read_text(encoding="utf-8", errors="replace")
    else:
        text = proc.stdout
        dest_xml.write_text(text, encoding="utf-8")
    if not text.strip():
        return ToolResult(False, "", None, "droidasc getmanifest returned an empty manifest", "none")
    return ToolResult(True, text, str(dest_xml), None, "manifest")


def get_class(apk: Path, class_name: str, dest: Path) -> ToolResult:
    if not droidasc_available():
        return _missing()
    class_name = validate_class_name(class_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(["droidasc", "getclass", str(apk), class_name, "-o", str(dest)])
    if proc.returncode != 0:
        return _failure(proc, "droidasc getclass failed")
    text = dest.read_text(encoding="utf-8", errors="replace") if dest.is_file() else proc.stdout
    if not text.strip():
        return ToolResult(False, "", None, "droidasc getclass returned empty output", "none")
    dest.write_text(text, encoding="utf-8")
    return ToolResult(True, text, str(dest), None, "java")


def disassemble(apk: Path, class_name: str, dest: Path) -> ToolResult:
    if not droidasc_available():
        return _missing()
    class_name = validate_class_name(class_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(["droidasc", "disassemble", str(apk), class_name, "-o", str(dest)])
    if proc.returncode != 0:
        return _failure(proc, "droidasc disassemble failed")
    text = dest.read_text(encoding="utf-8", errors="replace") if dest.is_file() else proc.stdout
    if not text.strip():
        return ToolResult(False, "", None, "droidasc disassemble returned empty output", "none")
    dest.write_text(text, encoding="utf-8")
    return ToolResult(True, text, str(dest), None, "smali")


def decompile_class(apk: Path, class_name: str, java_path: Path, smali_path: Path) -> ToolResult:
    """Decompile one class to Java-like source, then smali if that fails."""
    java = get_class(apk, class_name, java_path)
    if java.ok:
        return java
    if java.error == "droidasc not on PATH":
        return java
    smali = disassemble(apk, class_name, smali_path)
    if smali.ok:
        return smali
    smali.error = f"{java.error}; {smali.error}"
    return smali


def find_refs(
    apk: Path,
    kind: str,
    value: str,
    class_name: str | None = None,
) -> ToolResult:
    if not droidasc_available():
        return _missing()
    if kind not in _FIND_KINDS:
        raise ValueError(f"unsupported findrefs kind: {kind}")
    cleaned = value.strip()
    if not cleaned or cleaned.startswith("-") or any(char in cleaned for char in "\n\r\x00"):
        raise ValueError("invalid findrefs value")
    if len(cleaned) > 200:
        raise ValueError("findrefs value is too long")
    command = ["droidasc", "findrefs", str(apk), kind, cleaned]
    if class_name:
        command.extend(["--class", validate_class_name(class_name)])
    proc = _run(command)
    if proc.returncode != 0:
        return _failure(proc, "droidasc findrefs failed")
    text, _ = truncate(proc.stdout, MAX_CLASS_CHARS)
    return ToolResult(True, text, None, None, "findrefs")
