"""Statically carve a stage-1 payload out of an APK. Nothing is executed."""

from __future__ import annotations

import base64
import binascii
import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

_DEX = b"dex\n"
_ZIP = b"PK\x03\x04"
_B64 = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{8,}")
_INTERESTING = re.compile(
    r"https?://[^\s\"']+|L[A-Za-z0-9_$/]{3,};|[A-Za-z0-9_$.]+\.(?:apk|dex|so)"
)
_SKIP_PREFIXES = ("lib/", "META-INF/")
_MAX_FILES = 12
_MAX_BYTES = 4 * 1024 * 1024
_MAX_MEMBERS = 80
_MAX_BLOBS = 20
_MAX_STAGE_CLASSES = 6
_PACKER_MEMBER = re.compile(
    r"(jiagu|bangcle|ijiami|dexprotect|secneo|libshell|libdexhelper|libsecexe|pairip|fancybypass)"
)
_STUB_CODE = re.compile(
    r"jiagu|dexclassloader|inmemorydexclassloader|stubapp|shellapplication|pairip|fancybypass|np\.manager\.fucksign",
    re.IGNORECASE,
)
_CLASS_DESC = re.compile(rb"L(?!android/|java/|javax/|kotlin/|kotlinx/)[A-Za-z0-9_$/]{3,};")


def pack_reason(apk: Path | None, application_class: str | None, decompiled: str) -> str | None:
    """Why a sample should get a first-stage unpack, or None when it looks ordinary."""
    if application_class and _STUB_CODE.search(application_class):
        return "the application class looks like a packer stub"
    if decompiled and (_STUB_CODE.search(decompiled) or decompiled.count("\\u") >= 40):
        return "the decompiled code looks packed or obfuscated"
    if apk is None or not zipfile.is_zipfile(apk):
        return None
    with zipfile.ZipFile(apk) as archive:
        try:
            head = archive.read("classes.dex")[:4]
        except KeyError:
            head = b""
        if head and not head.startswith(_DEX):
            return "classes.dex is not a plain dex"
        for info in archive.infolist():
            name = info.filename.replace("\\", "/").lower()
            if name.startswith("assets/") and name.endswith(".dex"):
                return f"embedded dex {info.filename}"
            leaf = Path(name).name
            if _PACKER_MEMBER.search(leaf) or ".jiagu" in name:
                return f"packer member {info.filename}"
    return None


def first_stage_classes(stage_dir: Path) -> list[tuple[Path, str]]:
    """Class names from the first recovered DEX or APK. Nested payloads are not opened."""
    if not stage_dir.is_dir():
        return []
    files = sorted(
        path for path in stage_dir.iterdir()
        if path.is_file() and path.suffix in {".dex", ".apk", ".zip"}
    )
    found: list[tuple[Path, str]] = []
    for path in files:
        container, dex = _stage_container(path)
        if container is None or dex is None:
            continue
        for encoded in _CLASS_DESC.findall(dex):
            name = encoded[1:-1].decode("ascii", errors="ignore").replace("/", ".")
            if name and (container, name) not in found:
                found.append((container, name))
            if len(found) >= _MAX_STAGE_CLASSES:
                return found
        if found:
            return found
    return found


def _stage_container(path: Path) -> tuple[Path | None, bytes | None]:
    data = path.read_bytes()[:_MAX_BYTES]
    if data.startswith(_DEX):
        wrapped = path.with_name(f"{path.stem}-container.apk")
        if not wrapped.exists():
            with zipfile.ZipFile(wrapped, "w") as archive:
                archive.writestr("classes.dex", data)
        return wrapped, data
    if not data.startswith(_ZIP):
        return None, None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if Path(name).name == "classes.dex" and ".." not in Path(name).parts:
                    info = archive.getinfo(name)
                    if info.file_size <= _MAX_BYTES:
                        return path, archive.read(name)
    except zipfile.BadZipFile:
        return None, None
    return path, b""


@dataclass
class DecodedPayload:
    name: str
    kind: str
    via: str
    size: int
    detail: str


@dataclass
class Stage1Result:
    report: str
    payloads: list[DecodedPayload]


def unpack_stage1(source: Path, dest: Path) -> Stage1Result:
    """Save embedded DEX, APK, or encoded payloads and describe what they contain."""
    dest.mkdir(parents=True, exist_ok=True)
    blobs = _candidates(source)
    if not blobs:
        return Stage1Result("no stage-1 candidate was found in the APK", [])
    lines = ["stage-1 payloads:"]
    payloads: list[DecodedPayload] = []
    for name, data in blobs:
        if len(payloads) >= _MAX_FILES:
            lines.append(f"stopped after {_MAX_FILES} payloads")
            break
        kind, body, how = _decode(data)
        if kind is None or body is None:
            continue
        safe = _safe_name(name, len(payloads), kind)
        out = dest / safe
        out.write_bytes(body[:_MAX_BYTES])
        detail = _describe(kind, body).replace("\n", " ").strip()
        lines.append(f"- {safe} kind={kind} via={how} bytes={len(body)}")
        lines.append(_describe(kind, body))
        payloads.append(DecodedPayload(safe, kind, how, len(body), detail))
    if not payloads:
        return Stage1Result("no embedded stage-1 dex, apk, or encoded payload was decoded", [])
    return Stage1Result("\n".join(lines), payloads)


def _candidates(source: Path) -> list[tuple[str, bytes]]:
    if not source.is_file():
        return []
    if not zipfile.is_zipfile(source):
        data = source.read_bytes()[:_MAX_BYTES]
        return [(source.name, data)] if data else []
    found: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(source) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        for info in members[:_MAX_MEMBERS]:
            name = info.filename.replace("\\", "/")
            if name.startswith(_SKIP_PREFIXES) or name == "classes.dex" or info.file_size > _MAX_BYTES:
                continue
            if ".." in Path(name).parts:
                continue
            with archive.open(info) as handle:
                found.append((name, handle.read(_MAX_BYTES)))
    return found


def _decode(data: bytes) -> tuple[str | None, bytes | None, str]:
    kind = _kind(data)
    if kind:
        return kind, data, "embedded"
    decoded = _base64_payload(data)
    if decoded is not None:
        kind = _kind(decoded) or ("text" if _mostly_text(decoded) else None)
        if kind:
            return kind, decoded, "base64"
    xored = _xor_payload(data)
    if xored is not None:
        kind, body = xored
        return kind, body, "single-byte-xor"
    return None, None, ""


def _kind(data: bytes) -> str | None:
    if data.startswith(_DEX):
        return "dex"
    if data.startswith(_ZIP):
        return "apk" if _zip_has_manifest(data) else "zip"
    return None


def _base64_payload(data: bytes) -> bytes | None:
    chunks = _B64.findall(data)[:_MAX_BLOBS]
    if not chunks and _mostly_b64(data):
        chunks = [data.strip()]
    for chunk in chunks:
        try:
            decoded = base64.b64decode(chunk, validate=False)
        except (ValueError, binascii.Error):
            continue
        if len(decoded) >= 4 and (_kind(decoded) or _mostly_text(decoded)):
            return decoded
    return None


def _xor_payload(data: bytes) -> tuple[str, bytes] | None:
    if len(data) < 4 or len(data) > 1024 * 1024:
        return None
    for key in range(1, 256):
        magic = bytes(byte ^ key for byte in data[:4])
        if magic not in (_DEX, _ZIP):
            continue
        body = bytes(byte ^ key for byte in data)
        kind = _kind(body)
        if kind:
            return kind, body
    return None


def _describe(kind: str, body: bytes) -> str:
    if kind in {"apk", "zip"}:
        names = _zip_names(body)
        extra = ""
        nested = _nested_dex(body)
        if nested:
            extra = "\n  dex-strings: " + ", ".join(_interesting_strings(nested)[:12])
        shown = ", ".join(names[:20]) or "(no members)"
        return f"  members: {shown}{extra}"
    return "  strings: " + ", ".join(_interesting_strings(body)[:12] or ["(none)"])


def _interesting_strings(data: bytes) -> list[str]:
    found: list[str] = []
    for match in _PRINTABLE.findall(data):
        text = match.decode("ascii", errors="ignore")
        if _INTERESTING.search(text):
            found.append(text[:180])
    return found


def _zip_names(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return [info.filename.replace("\\", "/") for info in archive.infolist() if not info.is_dir()][:30]
    except zipfile.BadZipFile:
        return []


def _nested_dex(data: bytes) -> bytes | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if name.endswith(".dex") and ".." not in Path(name).parts:
                    info = archive.getinfo(name)
                    if info.file_size <= _MAX_BYTES:
                        return archive.read(name)
    except zipfile.BadZipFile:
        return None
    return None


def _zip_has_manifest(data: bytes) -> bool:
    return "AndroidManifest.xml" in _zip_names(data)


def _mostly_text(data: bytes) -> bool:
    if len(data) < 16:
        return False
    sample = data[:2000]
    printable = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in sample)
    return printable / len(sample) > 0.85


def _mostly_b64(data: bytes) -> bool:
    sample = data.strip()[:200]
    if len(sample) < 40:
        return False
    return all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r" for byte in sample)


def _safe_name(name: str, index: int, kind: str) -> str:
    base = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "payload"
    suffix = {"dex": ".dex", "apk": ".apk", "zip": ".zip", "text": ".txt"}.get(kind, ".bin")
    if not cleaned.endswith(suffix):
        cleaned = f"{cleaned}{suffix}"
    return f"{index:02d}-{cleaned}"
