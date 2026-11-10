"""Identify a cross-platform APK and unpack the payload that holds its logic.

The sample is never installed or executed. Java and Kotlin apps stay on the
DEX path. Other frameworks contribute text, string tables, or asset manifests
under framework/ so the analyst can read them.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from utils.limits import (
    EXCERPT_CHARS,
    MAX_FRAMEWORK_CHARS,
    MAX_FRAMEWORK_FILES,
    MAX_FRAMEWORK_READ,
    truncate,
)

_PRIORITY = (
    "flutter",
    "unity",
    "unreal",
    "react_native",
    "xamarin",
    "qt",
    "capacitor",
    "cordova",
)
_PREFER_LIBS = {
    "flutter": ("libapp.so",),
    "unity": ("libil2cpp.so", "libunity.so"),
    "unreal": ("libUnreal.so", "libUE4.so"),
}
_HERMES_PREFIX = bytes.fromhex("c61fbc03")
_DART_LIB = re.compile(rb"package:[A-Za-z0-9_$./]{1,160}\.dart")
_ASCII = re.compile(rb"[\x20-\x7e]{8,200}")
_TEXT_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm", ".json", ".css", ".qml"}
_RUNTIME_JS = {"cordova.js", "cordova.min.js", "phonegap.js", "capacitor.js"}


@dataclass
class Member:
    apk: Path
    name: str
    size: int


@dataclass
class FrameworkResult:
    name: str = "android"
    files: list[str] = field(default_factory=list)
    excerpts: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    prefer_libs: tuple[str, ...] = ()


def unpack_framework(apks: list[Path], case_dir: Path) -> FrameworkResult:
    catalog: list[Member] = []
    for apk in apks:
        catalog.extend(_catalog(apk))
    hits = _signals(member.name for member in catalog)
    if not hits:
        return FrameworkResult()
    name = next(item for item in _PRIORITY if item in hits)
    result = FrameworkResult(name=name, prefer_libs=_PREFER_LIBS.get(name, ()))
    others = sorted(hits - {name})
    if others:
        result.notes.append(f"also matched {', '.join(others)}")
    root = case_dir / "framework" / name
    written = _extract(name, catalog, root, case_dir, result)
    result.files = written
    if written:
        result.notes.insert(0, _summary(name, len(written)))
    else:
        result.notes.insert(0, f"{name} identified; no framework payload could be unpacked")
    return result


def _catalog(apk: Path) -> list[Member]:
    try:
        archive = zipfile.ZipFile(apk)
    except zipfile.BadZipFile:
        return []
    found: list[Member] = []
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            found.append(Member(apk, info.filename.replace("\\", "/"), info.file_size))
    return found


def _signals(names) -> set[str]:
    lower = [name.lower() for name in names]
    bases = {Path(name).name for name in lower}
    hits: set[str] = set()

    def has(name: str) -> bool:
        return name in bases

    def contains(fragment: str) -> bool:
        return any(fragment in name for name in lower)

    if has("libflutter.so") or contains("flutter_assets/"):
        hits.add("flutter")
    if has("libunity.so") or has("libil2cpp.so") or contains("global-metadata.dat"):
        hits.add("unity")
    if has("libue4.so") or has("libunreal.so"):
        hits.add("unreal")
    if (
        has("libreactnativejni.so")
        or has("libhermes.so")
        or has("libhermes_executor.so")
        or any(Path(name).name in {"index.android.bundle", "index.android.bundle.hbc"} for name in lower)
    ):
        hits.add("react_native")
    if (
        has("libmonodroid.so")
        or has("libmonosgen-2.0.so")
        or has("libxamarin-app.so")
        or any(name.startswith("assemblies/") and name.endswith(".dll") for name in lower)
    ):
        hits.add("xamarin")
    if any(base.startswith("libqt5") or base.startswith("libqt6") for base in bases):
        hits.add("qt")
    if has("capacitor.config.json") or has("capacitor.js"):
        hits.add("capacitor")
    if has("cordova.js") or has("cordova_plugins.js"):
        hits.add("cordova")
    return hits


def _summary(name: str, count: int) -> str:
    detail = {
        "flutter": "Dart AOT code stays in libapp.so; library URIs and asset manifests were extracted",
        "react_native": "JavaScript was extracted, or strings were taken from Hermes bytecode",
        "cordova": "web assets were extracted from assets/www",
        "capacitor": "web assets and Capacitor config were extracted",
        "xamarin": "assembly names and string literals were extracted",
        "unity": "managed strings or IL2CPP metadata strings were extracted",
        "qt": "QML and script files were extracted",
        "unreal": "cooked .pak assets were left packed; the engine library is preferred for native decompilation",
    }
    return f"framework {name}: {detail[name]} ({count} files)"


def _extract(
    name: str,
    catalog: list[Member],
    root: Path,
    case_dir: Path,
    result: FrameworkResult,
) -> list[str]:
    if name == "flutter":
        return _extract_flutter(catalog, root, case_dir, result)
    if name == "react_native":
        return _extract_react_native(catalog, root, case_dir, result)
    if name in {"cordova", "capacitor"}:
        return _extract_web(catalog, root, case_dir, result)
    if name == "xamarin":
        return _extract_dotnet(catalog, root, case_dir, result, assemblies=True)
    if name == "unity":
        return _extract_unity(catalog, root, case_dir, result)
    if name == "qt":
        return _extract_qt(catalog, root, case_dir, result)
    return []


def _extract_flutter(
    catalog: list[Member], root: Path, case_dir: Path, result: FrameworkResult
) -> list[str]:
    written: list[str] = []
    uris: list[str] = []
    for member in catalog:
        lower = member.name.lower()
        if Path(lower).name == "libapp.so":
            data = _read(member, MAX_FRAMEWORK_READ)
            if data is None:
                continue
            if member.size > len(data):
                result.notes.append("libapp.so string scan covered the first 2MB")
            uris.extend(match.decode("ascii") for match in _DART_LIB.findall(data))
        if "flutter_assets/" in lower and Path(lower).suffix in {".json", ".txt", ".xml"}:
            text = _read_text(member)
            if text:
                _store(member, text, root, case_dir, written, result)
    unique = sorted(set(uris))
    if unique:
        body = "\n".join(unique)
        _store_named("dart_libraries.txt", body, root, case_dir, written, result)
    return written


def _extract_react_native(
    catalog: list[Member], root: Path, case_dir: Path, result: FrameworkResult
) -> list[str]:
    written: list[str] = []
    bundles = [member for member in catalog if _is_bundle(member.name)]
    bundles.sort(key=lambda member: member.name)
    for member in bundles:
        data = _read(member, MAX_FRAMEWORK_READ)
        if data is None:
            continue
        if data.startswith(_HERMES_PREFIX):
            strings = _ascii_strings(data)
            body = "hermes bytecode strings\n" + "\n".join(strings)
            _store_named(f"{Path(member.name).name}.strings.txt", body, root, case_dir, written, result)
            result.notes.append(f"{Path(member.name).name} is Hermes bytecode, not JavaScript source")
            continue
        text = _decode_text(data)
        if text:
            _store(member, text, root, case_dir, written, result)
        else:
            body = "binary bundle strings\n" + "\n".join(_ascii_strings(data))
            _store_named(f"{Path(member.name).name}.strings.txt", body, root, case_dir, written, result)
    return written


def _extract_web(
    catalog: list[Member], root: Path, case_dir: Path, result: FrameworkResult
) -> list[str]:
    chosen = [member for member in catalog if _web_member(member.name)]
    chosen.sort(key=lambda member: _web_rank(member.name))
    written: list[str] = []
    for member in chosen:
        if len(written) >= MAX_FRAMEWORK_FILES:
            result.notes.append(f"framework extract kept {MAX_FRAMEWORK_FILES} files")
            break
        text = _read_text(member)
        if text:
            _store(member, text, root, case_dir, written, result)
    return written


def _extract_dotnet(
    catalog: list[Member],
    root: Path,
    case_dir: Path,
    result: FrameworkResult,
    *,
    assemblies: bool,
) -> list[str]:
    written: list[str] = []
    dlls = [member for member in catalog if member.name.lower().endswith(".dll")]
    if assemblies:
        dlls = [member for member in dlls if "assemblies/" in member.name.lower()] or dlls
    names = sorted({Path(member.name).name for member in dlls})
    if names:
        _store_named("assemblies.txt", "\n".join(names), root, case_dir, written, result)
    for member in dlls:
        if len(written) >= MAX_FRAMEWORK_FILES:
            break
        if Path(member.name).name.lower().startswith(("system.", "microsoft.", "mono.", "mscorlib")):
            continue
        data = _read(member, MAX_FRAMEWORK_READ)
        if not data:
            continue
        strings = _keep_app_strings(_ascii_strings(data) + _utf16_strings(data))
        if not strings:
            continue
        body = "\n".join(strings)
        _store_named(f"{Path(member.name).name}.strings.txt", body, root, case_dir, written, result)
    return written


def _extract_unity(
    catalog: list[Member], root: Path, case_dir: Path, result: FrameworkResult
) -> list[str]:
    written = _extract_dotnet(catalog, root, case_dir, result, assemblies=False)
    for member in catalog:
        if Path(member.name).name.lower() != "global-metadata.dat":
            continue
        data = _read(member, MAX_FRAMEWORK_READ)
        if not data:
            continue
        if len(data) >= 4 and data[:4] != b"\xaf\x1b\xb1\xfa":
            result.notes.append("global-metadata.dat did not start with the IL2CPP magic")
        body = "il2cpp metadata strings\n" + "\n".join(_ascii_strings(data))
        _store_named("global-metadata.strings.txt", body, root, case_dir, written, result)
        break
    return written


def _extract_qt(
    catalog: list[Member], root: Path, case_dir: Path, result: FrameworkResult
) -> list[str]:
    written: list[str] = []
    files = [
        member
        for member in catalog
        if Path(member.name).suffix.lower() in {".qml", ".js"} and "qml" in member.name.lower()
    ]
    for member in files:
        if len(written) >= MAX_FRAMEWORK_FILES:
            break
        text = _read_text(member)
        if text:
            _store(member, text, root, case_dir, written, result)
    return written


def _is_bundle(name: str) -> bool:
    base = Path(name.lower()).name
    return base in {"index.android.bundle", "index.android.bundle.js", "index.android.bundle.hbc"} or (
        name.lower().startswith("assets/") and base.endswith(".hbc")
    )


def _web_member(name: str) -> bool:
    lower = name.lower()
    base = Path(lower).name
    if base == "capacitor.config.json":
        return True
    web_root = lower.startswith("assets/www/") or lower.startswith("assets/public/")
    if not web_root or base in _RUNTIME_JS:
        return False
    return Path(lower).suffix in _TEXT_SUFFIXES


def _web_rank(name: str) -> tuple:
    base = Path(name.lower()).name
    order = {"index.html": 0, "cordova_plugins.js": 1, "capacitor.config.json": 0}
    return (order.get(base, 5), name)


def _safe_rel(name: str) -> str | None:
    parts = [part for part in name.replace("\\", "/").split("/") if part and part != "."]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _read(member: Member, limit: int) -> bytes | None:
    try:
        with zipfile.ZipFile(member.apk) as archive:
            info = archive.getinfo(member.name)
            with archive.open(info) as handle:
                return handle.read(limit)
    except (zipfile.BadZipFile, KeyError, OSError):
        return None


def _decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:512]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if sum(1 for char in text[:2000] if ord(char) < 9 or 13 < ord(char) < 32) > 20:
        return None
    return text


def _read_text(member: Member) -> str | None:
    data = _read(member, MAX_FRAMEWORK_READ)
    if data is None:
        return None
    return _decode_text(data)


def _ascii_strings(data: bytes, limit: int = 400) -> list[str]:
    found: list[str] = []
    for match in _ASCII.finditer(data):
        found.append(match.group().decode("ascii"))
        if len(found) >= limit:
            break
    return found


def _utf16_strings(data: bytes, limit: int = 200) -> list[str]:
    found: list[str] = []
    chars: list[str] = []
    for index in range(0, len(data) - 1, 2):
        code = data[index] | (data[index + 1] << 8)
        if 32 <= code < 127:
            chars.append(chr(code))
            continue
        if len(chars) >= 8:
            found.append("".join(chars))
            if len(found) >= limit:
                return found
        chars = []
    if len(chars) >= 8 and len(found) < limit:
        found.append("".join(chars))
    return found


def _keep_app_strings(values: list[str]) -> list[str]:
    skipped = ("System.", "Microsoft.", "Java.", "android.", "mono.", "mscorlib")
    kept: list[str] = []
    for value in values:
        if value.startswith(skipped):
            continue
        if value not in kept:
            kept.append(value)
        if len(kept) >= 200:
            break
    return kept


def _store(
    member: Member,
    text: str,
    root: Path,
    case_dir: Path,
    written: list[str],
    result: FrameworkResult,
) -> None:
    relative = _safe_rel(member.name)
    if relative is None or len(written) >= MAX_FRAMEWORK_FILES:
        return
    _store_named(relative, text, root, case_dir, written, result)


def _store_named(
    relative: str,
    text: str,
    root: Path,
    case_dir: Path,
    written: list[str],
    result: FrameworkResult,
) -> None:
    safe = _safe_rel(relative)
    if safe is None or len(written) >= MAX_FRAMEWORK_FILES:
        return
    dest = (root / safe).resolve()
    if not dest.is_relative_to(root.resolve()):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shown, _ = truncate(text, MAX_FRAMEWORK_CHARS)
    dest.write_text(shown, encoding="utf-8")
    rel = dest.relative_to(case_dir.resolve()).as_posix()
    written.append(rel)
    result.excerpts.append((rel, shown[:EXCERPT_CHARS]))
