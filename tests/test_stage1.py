import base64
import zipfile
from pathlib import Path

from tools.stage1 import first_stage_classes, pack_reason, unpack_stage1


def _apk(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\nouter")
        for name, payload in members.items():
            archive.writestr(name, payload)


def test_embedded_dex_strings_are_reported(tmp_path: Path):
    sample = tmp_path / "app.apk"
    _apk(sample, {"assets/stage.dex": b"dex\n035\x00https://collect.example/gate\x00"})
    result = unpack_stage1(sample, tmp_path / "stage1")
    assert "kind=dex" in result.report
    assert result.payloads[0].kind == "dex"
    assert "https://collect.example/gate" in result.report
    assert list((tmp_path / "stage1").glob("*.dex"))


def test_base64_and_xor_payloads_are_decoded(tmp_path: Path):
    dex = b"dex\n035\x00Lcom/example/Stage;\x00"
    sample = tmp_path / "app.apk"
    _apk(
        sample,
        {
            "assets/wrapped.b64": base64.b64encode(dex),
            "assets/packed.bin": bytes(byte ^ 0x2A for byte in dex),
        },
    )
    result = unpack_stage1(sample, tmp_path / "stage1")
    assert "via=base64" in result.report
    assert "via=single-byte-xor" in result.report
    assert {item.via for item in result.payloads} == {"base64", "single-byte-xor"}
    assert "Lcom/example/Stage;" in result.report


def test_plain_apk_is_not_treated_as_packed(tmp_path: Path):
    sample = tmp_path / "app.apk"
    _apk(sample, {})
    assert pack_reason(sample, "com.example.App", "class App { void onCreate() {} }") is None


def test_packed_sample_stops_at_the_first_stage(tmp_path: Path):
    dex = b"dex\n035\x00Lcom/hidden/Payload;\x00PK\x03\x04classes2.dex"
    sample = tmp_path / "app.apk"
    _apk(sample, {"assets/payload.dex": dex, "lib/arm64-v8a/libjiagu.so": b"\x7fELF"})
    assert pack_reason(sample, "com.example.App", "") is not None
    result = unpack_stage1(sample, tmp_path / "stage1")
    assert "kind=dex" in result.report
    saved = list((tmp_path / "stage1").glob("*"))
    assert not any(path.name == "classes2.dex" for path in saved)
    classes = first_stage_classes(tmp_path / "stage1")
    assert classes[0][1] == "com.hidden.Payload"
