"""Open an APK, XAPK, or APKS into a case directory."""

from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from tools.metadata import file_identity
from utils.limits import MAX_EXTRACT_BYTES, MAX_ZIP_MEMBERS

from schemas import FileIdentity


@dataclass
class UnpackedSample:
    container: str
    original: FileIdentity
    members: list[FileIdentity] = field(default_factory=list)
    apks: list[Path] = field(default_factory=list)
    base_apk: Path | None = None


def container_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".apk", ".xapk", ".apks"}:
        return suffix[1:]
    raise ValueError(f"unsupported sample type: {path.name}")


def _safe_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    parts = Path(normalized).parts
    if not normalized or normalized.startswith("/") or ".." in parts:
        raise ValueError(f"unsafe zip member: {name}")
    return Path(normalized).name


def _is_split(name: str) -> bool:
    base = Path(name).name
    return base.startswith("config.") or base.startswith("split_") or ".config." in base


def _apk_has_manifest(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except zipfile.BadZipFile:
        return False


def pick_base_apk(apks: list[Path]) -> Path | None:
    if not apks:
        return None
    named = [path for path in apks if path.name == "base.apk"]
    if named:
        return named[0]
    with_manifest = [
        path for path in apks if not _is_split(path.name) and _apk_has_manifest(path)
    ]
    pool = with_manifest or [path for path in apks if not _is_split(path.name)] or apks
    return max(pool, key=lambda path: path.stat().st_size)


def _hash_zip_members(path: Path) -> list[FileIdentity]:
    identities: list[FileIdentity] = []
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > MAX_ZIP_MEMBERS:
            raise ValueError(f"zip has {len(members)} members; limit is {MAX_ZIP_MEMBERS}")
        for info in members:
            _safe_member_name(info.filename)
            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("zip uncompressed size exceeds the extract limit")
            digest_md5, digest_sha1, digest_sha256 = _new_digests()
            with archive.open(info) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest_md5.update(chunk)
                    digest_sha1.update(chunk)
                    digest_sha256.update(chunk)
            identities.append(
                FileIdentity(
                    name=info.filename.replace("\\", "/"),
                    size=info.file_size,
                    md5=digest_md5.hexdigest(),
                    sha1=digest_sha1.hexdigest(),
                    sha256=digest_sha256.hexdigest(),
                )
            )
    return identities


def _new_digests():
    import hashlib

    return hashlib.md5(), hashlib.sha1(), hashlib.sha256()


def _extract_apks(archive_path: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            filename = _safe_member_name(info.filename)
            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("zip uncompressed size exceeds the extract limit")
            target = dest / filename
            if target.exists():
                target = dest / f"{len(written)}_{filename}"
            with archive.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            written.append(target)
    return written


def unpack_sample(
    sample: Path, case_dir: Path, original: FileIdentity | None = None
) -> UnpackedSample:
    sample = sample.resolve()
    if not sample.is_file():
        raise FileNotFoundError(sample)
    kind = container_kind(sample)
    original = original or file_identity(sample)
    apk_dir = case_dir / "apks"
    apk_dir.mkdir(parents=True, exist_ok=True)

    if kind == "apk":
        target = apk_dir / sample.name
        shutil.copy2(sample, target)
        apks = [target]
        members: list[FileIdentity] = []
    else:
        members = _hash_zip_members(sample)
        apks = _extract_apks(sample, apk_dir)
        if not apks:
            raise ValueError(f"{sample.name} does not contain an APK")

    return UnpackedSample(
        container=kind,
        original=original,
        members=members,
        apks=apks,
        base_apk=pick_base_apk(apks),
    )
