import hashlib
import zipfile
from pathlib import Path

import pytest

from tools.unpack import pick_base_apk, unpack_sample


def _apk(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)


def test_unpack_xapk_picks_base_and_hashes_members(tmp_path: Path):
    base = tmp_path / "base.apk"
    split = tmp_path / "config.arm64_v8a.apk"
    _apk(base, {"AndroidManifest.xml": b"<manifest/>"})
    _apk(split, {"lib/arm64-v8a/libdemo.so": b"\x7fELF"})
    sample = tmp_path / "app.xapk"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.write(base, "base.apk")
        archive.write(split, "config.arm64_v8a.apk")

    unpacked = unpack_sample(sample, tmp_path / "case")
    assert unpacked.container == "xapk"
    assert unpacked.base_apk is not None
    assert unpacked.base_apk.name == "base.apk"
    assert {path.name for path in unpacked.apks} == {"base.apk", "config.arm64_v8a.apk"}
    assert {item.name for item in unpacked.members} == {"base.apk", "config.arm64_v8a.apk"}
    base_member = next(item for item in unpacked.members if item.name == "base.apk")
    assert base_member.sha256 == hashlib.sha256(base.read_bytes()).hexdigest()
    assert unpacked.original.sha256 == hashlib.sha256(sample.read_bytes()).hexdigest()


def test_pick_base_skips_config_split_when_another_apk_has_a_manifest(tmp_path: Path):
    plain = tmp_path / "com.example.apk"
    split = tmp_path / "split_config.xxhdpi.apk"
    _apk(plain, {"AndroidManifest.xml": b"<manifest/>"})
    _apk(split, {"resources.arsc": b"x"})
    assert pick_base_apk([split, plain]) == plain


def test_unpack_rejects_zip_slip(tmp_path: Path):
    sample = tmp_path / "bad.xapk"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("../evil.apk", b"nope")
    with pytest.raises(ValueError, match="unsafe zip member"):
        unpack_sample(sample, tmp_path / "case")
