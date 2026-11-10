"""In-process tools bound to one case directory."""

from __future__ import annotations

from pathlib import Path
from typing import NotRequired, TypedDict

from claude_agent_sdk import create_sdk_mcp_server, tool

from tools.dex_decompiler import (
    class_filename,
    decompile_class,
    disassemble,
    find_refs,
    validate_class_name,
)
from tools.native_decompiler import decompile_symbol
from tools.stage1 import unpack_stage1
from utils.limits import PAGE_CHARS, truncate
from utils.untrusted import fence

SERVER_NAME = "case"
TOOL_NAMES = ("read_artifact", "decompile_class", "find_refs", "decompile_native", "unpack_stage1")
ALLOWED_TOOLS = [f"mcp__{SERVER_NAME}__{name}" for name in TOOL_NAMES]


class ReadArgs(TypedDict):
    path: str
    offset: NotRequired[int]
    limit: NotRequired[int]


class DecompileArgs(TypedDict):
    class_name: str
    mode: NotRequired[str]


class FindArgs(TypedDict, total=False):
    kind: str
    value: str
    query: str
    name: str
    class_name: str
    path: str
    file: str


def _loose_schema(*names: str) -> dict:
    return {
        "type": "object",
        "additionalProperties": True,
        "properties": {name: {} for name in names},
    }


FIND_SCHEMA = _loose_schema("kind", "value", "query", "name", "class_name", "class", "path", "file")
READ_SCHEMA = _loose_schema("path", "file", "name", "class_name", "class", "offset", "limit")
DECOMPILE_SCHEMA = _loose_schema("class_name", "class", "name", "path", "file", "mode")
NATIVE_SCHEMA = _loose_schema("library", "path", "file", "soname", "function", "symbol", "name", "method")
STAGE_SCHEMA = _loose_schema("path", "file")
_MANIFEST_KINDS = {
    "manifest",
    "permission",
    "permissions",
    "component",
    "components",
    "activity",
    "service",
    "receiver",
    "provider",
}


class NativeArgs(TypedDict):
    library: str
    function: str


class Stage1Args(TypedDict):
    path: NotRequired[str]


def _text(body: str, nonce: str, *, error: bool = False, full: bool = False) -> dict:
    shown = body if full else truncate(body, PAGE_CHARS)[0]
    payload: dict = {"content": [{"type": "text", "text": fence(shown, nonce)}]}
    if error:
        payload["is_error"] = True
    return payload


def resolve_inside(case_dir: Path, relative: str) -> Path:
    if not relative or relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
        raise ValueError("path escapes the case directory")
    path = (case_dir / relative).resolve()
    if not path.is_relative_to(case_dir.resolve()):
        raise ValueError("path escapes the case directory")
    return path


def _arg(args: dict, *names: str) -> str:
    for name in names:
        raw = args.get(name)
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return text
    return ""


def manifest_request(args: dict) -> bool:
    """True when the caller is searching the manifest rather than DEX code."""
    kind = _arg(args, "kind").lower()
    path = _arg(args, "path", "file")
    class_name = _arg(args, "class_name", "class")
    blob = f"{kind} {path} {class_name}".lower()
    if "manifest" in blob or path.lower().endswith(".xml"):
        return True
    return kind in _MANIFEST_KINDS


def search_manifest(text: str, kind: str, value: str) -> str:
    kind = kind.lower()
    lines = text.splitlines()
    if kind in {"permission", "permissions"} and not value:
        hits = [
            f"{index}: {line.strip()}"
            for index, line in enumerate(lines, 1)
            if "permission" in line.lower()
        ]
        return "\n".join(hits) or "no permissions in the manifest"
    if not value:
        return text
    hits = [f"{index}: {line.strip()}" for index, line in enumerate(lines, 1) if value in line]
    if hits:
        return "\n".join(hits)
    return f"no manifest line contains {value}"


def _number(args: dict, name: str, default: int = 0) -> int:
    raw = args.get(name, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def class_from_reference(raw: str) -> str:
    text = raw.strip().replace("\\", "/")
    if text.startswith("L") and text.endswith(";"):
        text = text[1:-1].replace("/", ".")
    name = Path(text).name
    for suffix in (".java", ".smali", ".kt", ".txt"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def resolve_case_file(case_dir: Path, raw: str) -> Path:
    text = raw.strip().replace("\\", "/")
    if Path(text).name.lower() in {"androidmanifest.xml", "manifest"}:
        text = "manifest.xml"
    if "/" in text or Path(text).suffix:
        try:
            direct = resolve_inside(case_dir, text)
        except ValueError:
            direct = None
        else:
            if direct.is_file():
                return direct
    stem = class_from_reference(text)
    if not stem or any(char in stem for char in "*?[]"):
        raise ValueError(f"file not found: {raw}")
    suffixes = {".java", ".smali", ".kt", ".txt", ".xml"}
    matches = [
        path
        for path in case_dir.rglob(f"{stem}.*")
        if path.is_file() and path.suffix.lower() in suffixes
    ]
    if not matches and Path(text).suffix and not any(char in Path(text).name for char in "*?[]"):
        matches = [path for path in case_dir.rglob(Path(text).name) if path.is_file()]
    if not matches:
        raise ValueError(f"file not found: {raw}")

    def rank(path: Path) -> tuple:
        parts = path.parts
        bucket = 0 if "dex" in parts else 1 if "stage1" in parts else 2
        return (bucket, len(parts), path.as_posix())

    matches.sort(key=rank)
    return matches[0]


def resolve_library(case_dir: Path, raw: str) -> Path:
    text = raw.strip().replace("\\", "/")
    name = Path(text).name
    if name.endswith(".txt"):
        name = name[:-4]
    if "/" in text:
        try:
            direct = resolve_inside(case_dir, text)
        except ValueError:
            direct = None
        else:
            if direct.is_file() and direct.suffix == ".so":
                return direct
    root = case_dir / "native"
    if not name.endswith(".so") or any(char in name for char in "*?[]") or not root.is_dir():
        raise ValueError(f"library not found: {raw}")
    found = [path for path in root.rglob(name) if path.is_file()]
    if not found:
        raise ValueError(f"library not found: {raw}")
    found.sort(key=lambda path: (0 if "arm64-v8a" in path.parts else 1, path.as_posix()))
    return found[0]


def clean_symbol(raw: str) -> str:
    text = raw.strip()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    return text


def source_in_full(relative: str) -> bool:
    """Decompiled Java and native pseudocode are returned whole."""
    path = Path(relative)
    if path.suffix.lower() in {".java", ".kt", ".smali"}:
        return True
    return path.parts[:2] == ("native", "notes")


def read_case_text(path: Path, relative: str, offset: int = 0, limit: int = 0) -> str:
    data = path.read_bytes()
    if b"\x00" in data[:512]:
        return f"{path.name} is binary ({len(data)} bytes)."
    text = data.decode("utf-8", errors="replace")
    if source_in_full(relative):
        start = 0
        page = text
    else:
        start = max(0, offset)
        size = PAGE_CHARS if limit <= 0 else min(limit, PAGE_CHARS)
        page = text[start : start + size]
    return f"path={path.name} offset={start} length={len(text)}\n{page}"


def build_case_server(case_dir: Path, base_apk: Path | None, nonce: str):
    case_dir = case_dir.resolve()

    @tool(
        "read_artifact",
        "Read decompiled Java, native pseudocode, or another text file in this case. path can be a case-relative file or a class name.",
        READ_SCHEMA,
    )
    async def read_artifact(args: ReadArgs) -> dict:
        raw = _arg(args, "path", "file", "name", "class_name", "class")
        if not raw:
            return _text("read_artifact needs a case path or a class name", nonce, error=True)
        try:
            path = resolve_case_file(case_dir, raw)
        except ValueError as exc:
            return _text(str(exc), nonce, error=True)
        relative = path.relative_to(case_dir).as_posix()
        return _text(
            read_case_text(path, relative, _number(args, "offset"), _number(args, "limit")),
            nonce,
            full=source_in_full(relative),
        )

    @tool(
        "decompile_class",
        "Decompile one DEX class from the base APK. class_name can be a class or a decompiled file path. mode is java or smali.",
        DECOMPILE_SCHEMA,
    )
    async def decompile_class_tool(args: DecompileArgs) -> dict:
        if base_apk is None:
            return _text("no base APK in this case", nonce, error=True)
        raw = _arg(args, "class_name", "class", "name", "path", "file")
        if not raw:
            return _text("decompile_class needs a class name", nonce, error=True)
        try:
            class_name = validate_class_name(class_from_reference(raw))
        except ValueError as exc:
            return _text(str(exc), nonce, error=True)
        mode = _arg(args, "mode").lower() or "java"
        out_dir = case_dir / "ondemand"
        if mode == "smali":
            dest = out_dir / class_filename(class_name, "smali")
            result = disassemble(base_apk, class_name, dest)
        elif mode == "java":
            result = decompile_class(
                base_apk,
                class_name,
                out_dir / class_filename(class_name, "java"),
                out_dir / class_filename(class_name, "smali"),
            )
        else:
            return _text("mode must be java or smali", nonce, error=True)
        if not result.ok:
            return _text(result.error or "decompile failed", nonce, error=True)
        rel = Path(result.path or "").resolve().relative_to(case_dir).as_posix()
        return _text(f"path={rel} backend={result.backend}\n{result.text}", nonce, full=True)

    @tool(
        "find_refs",
        "Find a DEX reference, or a line in the manifest. DEX kind is string, type, method, or field. To check a permission or component, pass path manifest.xml and the name as value. Do not pass the manifest as class_name.",
        FIND_SCHEMA,
    )
    async def find_refs_tool(args: FindArgs) -> dict:
        if manifest_request(args):
            manifest = case_dir / "manifest.xml"
            if not manifest.is_file():
                return _text("manifest.xml is not in this case", nonce, error=True)
            text = manifest.read_text(encoding="utf-8", errors="replace")
            return _text(search_manifest(text, _arg(args, "kind"), _arg(args, "value", "query", "name")), nonce, full=True)
        if base_apk is None:
            return _text("no base APK in this case", nonce, error=True)
        kind = _arg(args, "kind").lower()
        kind = {"str": "string", "strings": "string", "methods": "method", "fields": "field", "types": "type"}.get(kind, kind)
        value = _arg(args, "value", "query", "name")
        class_name = class_from_reference(_arg(args, "class_name", "class")) or None
        if class_name and ("/" in class_name or class_name.endswith(".xml")):
            class_name = None
        if not kind or not value:
            return _text(
                "find_refs needs kind (string, type, method, or field) and value. For the manifest, pass path manifest.xml.",
                nonce,
                error=True,
            )
        try:
            result = find_refs(base_apk, kind, value, class_name)
        except ValueError as exc:
            return _text(str(exc), nonce, error=True)
        if not result.ok:
            return _text(result.error or "findrefs failed", nonce, error=True)
        return _text(result.text or "(no references)", nonce)

    @tool(
        "decompile_native",
        "Decompile one function from an extracted native library under native/. library can be the .so path or the file name. function can be the symbol, with or without a signature.",
        NATIVE_SCHEMA,
    )
    async def decompile_native_tool(args: NativeArgs) -> dict:
        library = _arg(args, "library", "path", "file", "soname")
        function = clean_symbol(_arg(args, "function", "symbol", "method", "name"))
        if not library or not function:
            return _text("decompile_native needs a library and a function", nonce, error=True)
        try:
            path = resolve_library(case_dir, library)
        except ValueError as exc:
            return _text(str(exc), nonce, error=True)
        if path.suffix != ".so" or "native" not in path.relative_to(case_dir).parts:
            return _text("library must be an extracted .so under native/", nonce, error=True)
        try:
            body, error = decompile_symbol(path, function)
        except ValueError as exc:
            return _text(str(exc), nonce, error=True)
        if error:
            return _text(error, nonce, error=True)
        return _text(body, nonce, full=True)

    @tool(
        "unpack_stage1",
        "Statically unpack the first embedded DEX, APK, or encoded payload. path is an optional case-relative file outside stage1/; omit it to scan the base APK. A file already under stage1/ is not unpacked. Nothing is executed.",
        STAGE_SCHEMA,
    )
    async def unpack_stage1_tool(args: Stage1Args) -> dict:
        relative = _arg(args, "path", "file")
        if relative:
            try:
                source = resolve_inside(case_dir, relative)
            except ValueError as exc:
                return _text(str(exc), nonce, error=True)
            if not source.is_file():
                return _text("file not found", nonce, error=True)
            stage_root = (case_dir / "stage1").resolve()
            if source.resolve() == stage_root or stage_root in source.resolve().parents:
                return _text("only the first stage is unpacked", nonce, error=True)
        elif base_apk is None:
            return _text("no base APK in this case", nonce, error=True)
        else:
            source = base_apk
        unpacked = unpack_stage1(source, case_dir / "stage1")
        return _text(unpacked.report, nonce)

    return create_sdk_mcp_server(
        name=SERVER_NAME,
        version="1.0.0",
        tools=[read_artifact, decompile_class_tool, find_refs_tool, decompile_native_tool, unpack_stage1_tool],
    )
