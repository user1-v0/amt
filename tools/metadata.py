"""Hashes and AndroidManifest facts. The manifest text comes from droidasc."""

from __future__ import annotations

import hashlib
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from schemas import Component, FileIdentity, Fingerprint

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_KINDS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def file_identity(path: Path) -> FileIdentity:
    digest_md5 = hashlib.md5()
    digest_sha1 = hashlib.sha1()
    digest_sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest_md5.update(chunk)
            digest_sha1.update(chunk)
            digest_sha256.update(chunk)
    return FileIdentity(
        name=path.name,
        size=size,
        md5=digest_md5.hexdigest(),
        sha1=digest_sha1.hexdigest(),
        sha256=digest_sha256.hexdigest(),
    )


def signature_fingerprints(apk: Path) -> list[Fingerprint]:
    """Hash the APK signature files. These are identity fingerprints, not code."""
    found: list[Fingerprint] = []
    try:
        archive = zipfile.ZipFile(apk)
    except zipfile.BadZipFile:
        return found
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            upper = name.upper()
            if not upper.startswith("META-INF/"):
                continue
            if not (
                upper.endswith((".RSA", ".DSA", ".EC", ".SF")) or upper.endswith("MANIFEST.MF")
            ):
                continue
            digest = hashlib.sha256()
            with archive.open(info) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            found.append(Fingerprint(kind="signature", name=name, sha256=digest.hexdigest()))
            if len(found) >= 12:
                break
    return found


def file_fingerprints(identity: FileIdentity) -> list[Fingerprint]:
    return [
        Fingerprint(kind="file", name=f"{identity.name} sha256", sha256=identity.sha256),
        Fingerprint(kind="file", name=f"{identity.name} sha1", sha256=identity.sha1),
        Fingerprint(kind="file", name=f"{identity.name} md5", sha256=identity.md5),
    ]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _android_attr(elem: ET.Element, name: str) -> str | None:
    return elem.get(f"{{{ANDROID_NS}}}{name}") or elem.get(f"android:{name}")


def _exported(raw: str | None) -> bool | None:
    if raw is None:
        return None
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def split_label(raw: str | None) -> tuple[str | None, str | None]:
    if raw is None or raw == "":
        return None, None
    if raw.startswith("@") or raw.startswith("?"):
        return None, raw
    return raw, None


def resolve_class_name(name: str, package: str | None) -> str:
    if name.startswith(".") and package:
        return f"{package}{name}"
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _actions(elem: ET.Element) -> list[str]:
    found: list[str] = []
    for node in elem.iter():
        if _local(node.tag) != "action":
            continue
        name = _android_attr(node, "name")
        if name and name not in found:
            found.append(name)
    return found


@dataclass
class ManifestFacts:
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    app_label: str | None = None
    app_label_ref: str | None = None
    application_class: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)


def parse_manifest_xml(text: str) -> ManifestFacts:
    if len(text) > 2_000_000:
        raise ValueError("manifest XML exceeds the parse limit")
    root = ET.fromstring(text)
    facts = ManifestFacts(
        package=root.get("package"),
        version_name=_android_attr(root, "versionName"),
        version_code=_android_attr(root, "versionCode"),
    )
    for node in root:
        kind = _local(node.tag)
        if kind in {"uses-permission", "uses-permission-sdk-23"}:
            name = _android_attr(node, "name")
            if name and name not in facts.permissions:
                facts.permissions.append(name)
    application = next((node for node in root if _local(node.tag) == "application"), None)
    if application is not None:
        label, label_ref = split_label(_android_attr(application, "label"))
        facts.app_label = label
        facts.app_label_ref = label_ref
        app_name = _android_attr(application, "name")
        if app_name:
            facts.application_class = resolve_class_name(app_name, facts.package)
        for child in list(application):
            kind = _COMPONENT_KINDS.get(_local(child.tag))
            if kind is None:
                continue
            name = _android_attr(child, "name") or _android_attr(child, "targetActivity")
            if not name:
                continue
            facts.components.append(
                Component(
                    kind=kind,
                    name=resolve_class_name(name, facts.package),
                    exported=_exported(_android_attr(child, "exported")),
                    actions=_actions(child),
                )
            )
    return facts
