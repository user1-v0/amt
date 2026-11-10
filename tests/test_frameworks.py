import zipfile
from pathlib import Path

from tools.frameworks import unpack_framework
from tools.native_decompiler import SoMember, select_native


def _apk(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def test_plain_apk_stays_android(tmp_path: Path):
    sample = tmp_path / "app.apk"
    _apk(sample, {"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex\n"})
    result = unpack_framework([sample], tmp_path / "case")
    assert result.name == "android"
    assert result.files == []


def test_react_native_javascript_is_extracted(tmp_path: Path):
    sample = tmp_path / "app.apk"
    script = "function start(){ fetch('https://collect.example/gate'); }\n"
    _apk(
        sample,
        {
            "lib/arm64-v8a/libreactnativejni.so": b"\x7fELF",
            "assets/index.android.bundle": script.encode(),
        },
    )
    case = tmp_path / "case"
    result = unpack_framework([sample], case)
    assert result.name == "react_native"
    assert result.files
    stored = (case / result.files[0]).read_text(encoding="utf-8")
    assert "https://collect.example/gate" in stored
    assert result.excerpts[0][1].startswith("function start")


def test_hermes_bundle_becomes_strings(tmp_path: Path):
    sample = tmp_path / "app.apk"
    payload = bytes.fromhex("c61fbc03") + b"\x00" * 16 + b"https://collect.example/hermes" + b"\x00"
    _apk(sample, {"assets/index.android.bundle": payload, "lib/arm64-v8a/libhermes.so": b"\x7fELF"})
    case = tmp_path / "case"
    result = unpack_framework([sample], case)
    assert result.name == "react_native"
    text = (case / result.files[0]).read_text(encoding="utf-8")
    assert "hermes bytecode strings" in text
    assert "https://collect.example/hermes" in text
    assert any("Hermes bytecode" in note for note in result.notes)


def test_cordova_extracts_www_and_rejects_zip_slip(tmp_path: Path):
    sample = tmp_path / "app.apk"
    _apk(
        sample,
        {
            "assets/www/cordova.js": b"cordova runtime",
            "assets/www/index.html": b"<html>send location</html>",
            "assets/www/../../outside.txt": b"escaped",
        },
    )
    case = tmp_path / "case"
    result = unpack_framework([sample], case)
    assert result.name == "cordova"
    assert any(path.endswith("index.html") for path in result.files)
    assert not any("outside" in path for path in result.files)
    assert not (tmp_path / "outside.txt").exists()
    html = next(path for path in result.files if path.endswith("index.html"))
    assert "send location" in (case / html).read_text(encoding="utf-8")
    assert not any(path.endswith("cordova.js") for path in result.files)


def test_flutter_extracts_dart_uris_and_assets(tmp_path: Path):
    sample = tmp_path / "app.apk"
    libapp = b"\x7fELF" + b"\x00" * 32 + b"package:evil/main.dart" + b"\x00"
    _apk(
        sample,
        {
            "lib/arm64-v8a/libflutter.so": b"\x7fELF",
            "lib/arm64-v8a/libapp.so": libapp,
            "flutter_assets/AssetManifest.json": b'{"assets/config.json":["assets/config.json"]}',
        },
    )
    case = tmp_path / "case"
    result = unpack_framework([sample], case)
    assert result.name == "flutter"
    assert result.prefer_libs == ("libapp.so",)
    libraries = next(path for path in result.files if path.endswith("dart_libraries.txt"))
    assert "package:evil/main.dart" in (case / libraries).read_text(encoding="utf-8")
    assert any(path.endswith("AssetManifest.json") for path in result.files)


def test_xamarin_lists_assemblies_and_strings(tmp_path: Path):
    sample = tmp_path / "app.apk"
    dll = (
        b"MZ"
        + "System.Object".encode("utf-16le")
        + b"\x00\x00"
        + "UploadSms".encode("utf-16le")
        + b"\x00\x00"
    )
    _apk(
        sample,
        {
            "lib/arm64-v8a/libmonodroid.so": b"\x7fELF",
            "assemblies/System.Private.CoreLib.dll": b"MZ",
            "assemblies/App.dll": dll,
        },
    )
    case = tmp_path / "case"
    result = unpack_framework([sample], case)
    assert result.name == "xamarin"
    names = (case / "framework/xamarin/assemblies.txt").read_text(encoding="utf-8")
    assert "App.dll" in names
    strings = (case / "framework/xamarin/App.dll.strings.txt").read_text(encoding="utf-8")
    assert "UploadSms" in strings
    assert "System.Object" not in strings


def test_preferred_native_library_is_decompiled_with_the_rest():
    def member(soname: str) -> SoMember:
        return SoMember("a.apk", "a.apk", f"lib/arm64-v8a/{soname}", "arm64-v8a", soname, 10)

    chosen = select_native(
        [member(f"lib{index:02d}.so") for index in range(9)] + [member("libapp.so")],
        prefer=("libapp.so",),
    )
    assert chosen[0].soname == "libapp.so"
    assert len(chosen) == 10
