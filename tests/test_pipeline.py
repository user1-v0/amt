import asyncio
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from agent import main
from pipeline import CaseBundle, analyze, build_case
from tools.dex_decompiler import ToolResult, get_manifest, validate_class_name
from tools.mcp_server import (
    FIND_SCHEMA,
    READ_SCHEMA,
    _text,
    build_case_server,
    class_from_reference,
    clean_symbol,
    manifest_request,
    read_case_text,
    resolve_case_file,
    resolve_inside,
    resolve_library,
    search_manifest,
    source_in_full,
)
from utils.limits import PAGE_CHARS
from agents.verifier import align_verification
from agents.verdict import verdict_prompt
from schemas import Evidence, FileIdentity, Finding, SampleFacts, Verification


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application android:name=".App" android:label="Demo">
    <activity android:name=".Main" android:exported="true"/>
    <service android:name=".Worker" android:exported="false"/>
  </application>
</manifest>
"""


def _apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
        archive.writestr("lib/x86/libdemo.so", b"\x7fELF")


def test_build_case_writes_facts_without_external_tools(monkeypatch, tmp_path: Path):
    def fake_manifest(apk: Path, dest: Path) -> ToolResult:
        dest.write_text(MANIFEST, encoding="utf-8")
        return ToolResult(True, MANIFEST, str(dest), None, "manifest")

    def fake_decompile(apk: Path, class_name: str, java_path: Path, smali_path: Path) -> ToolResult:
        java_path.parent.mkdir(parents=True, exist_ok=True)
        text = f"class {class_name} {{ void onCreate() {{}} }}"
        java_path.write_text(text, encoding="utf-8")
        return ToolResult(True, text, str(java_path), None, "java")

    def fake_analyze(so_path: Path, java_refs=None):
        return ["Java_com_example_App_start"], "listing only", False, "r2ghidra pdg is unavailable"

    monkeypatch.setattr("pipeline.get_manifest", fake_manifest)
    monkeypatch.setattr("pipeline.droidasc_available", lambda: True)
    monkeypatch.setattr("pipeline.decompile_class", fake_decompile)
    monkeypatch.setattr("tools.native_decompiler.analyze_so", fake_analyze)

    sample = tmp_path / "app.apk"
    _apk(sample)
    bundle = build_case(sample, tmp_path / "workspace")

    assert bundle.facts.package == "com.example.app"
    assert bundle.facts.framework == "android"
    assert bundle.facts.app_label == "Demo"
    assert bundle.facts.original.sha256
    assert bundle.facts.components[0].kind == "application"
    main_component = next(item for item in bundle.facts.components if item.name.endswith(".Main"))
    assert main_component.exported is True
    assert main_component.status == "ok"
    assert main_component.decompile_path is not None
    assert (bundle.case_dir / main_component.decompile_path).is_file()
    worker = next(item for item in bundle.facts.components if item.name.endswith(".Worker"))
    assert worker.exported is False
    assert worker.status == "ok"
    assert worker.decompile_path is not None
    assert (bundle.case_dir / worker.decompile_path).is_file()
    assert len(bundle.facts.native_libs) == 1
    assert bundle.facts.native_libs[0].abi == "arm64-v8a"
    assert bundle.facts.native_libs[0].pseudocode is False
    saved = json.loads((bundle.case_dir / "case.json").read_text(encoding="utf-8"))
    assert saved["facts"]["package"] == "com.example.app"
    assert "sha256" in bundle.pack_text
    assert "com.example.app" in bundle.pack_text
    assert "void onCreate" in bundle.pack_text
    assert "fingerprints:" in bundle.pack_text
    assert bundle.facts.original.sha256 in bundle.pack_text
    assert "listing only" in bundle.pack_text
    assert all(item.status != "pending" for item in bundle.facts.components)
    assert not (bundle.case_dir / "stage1").exists()


def test_packed_sample_is_unpacked_once(monkeypatch, tmp_path: Path):
    def fake_manifest(apk: Path, dest: Path) -> ToolResult:
        dest.write_text(MANIFEST, encoding="utf-8")
        return ToolResult(True, MANIFEST, str(dest), None, "manifest")

    def fake_decompile(apk: Path, class_name: str, java_path: Path, smali_path: Path) -> ToolResult:
        java_path.parent.mkdir(parents=True, exist_ok=True)
        text = f"class {class_name} {{}}"
        java_path.write_text(text, encoding="utf-8")
        return ToolResult(True, text, str(java_path), None, "java")

    monkeypatch.setattr("pipeline.get_manifest", fake_manifest)
    monkeypatch.setattr("pipeline.droidasc_available", lambda: True)
    monkeypatch.setattr("pipeline.decompile_class", fake_decompile)
    monkeypatch.setattr(
        "tools.native_decompiler.analyze_so",
        lambda so_path, java_refs=None: ([], "", False, None),
    )

    sample = tmp_path / "packed.apk"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF")
        archive.writestr("assets/payload.dex", b"dex\n035\x00Lcom/hidden/Payload;\x00")
    bundle = build_case(sample, tmp_path / "workspace")

    assert bundle.facts.payloads[0].kind == "dex"
    assert any("first stage only" in note for note in bundle.facts.stage_notes)
    assert (bundle.case_dir / "stage1" / "report.txt").is_file()
    assert (bundle.case_dir / "stage1" / "src").is_dir()
    assert "com.hidden.Payload" in bundle.pack_text
    assert "classes2.dex" not in bundle.pack_text


def test_every_component_and_library_is_decompiled(monkeypatch, tmp_path: Path):
    def fake_manifest(apk: Path, dest: Path) -> ToolResult:
        dest.write_text(MANIFEST, encoding="utf-8")
        return ToolResult(True, MANIFEST, str(dest), None, "manifest")

    def fake_decompile(apk: Path, class_name: str, java_path: Path, smali_path: Path) -> ToolResult:
        java_path.parent.mkdir(parents=True, exist_ok=True)
        text = f"class {class_name} {{}}"
        java_path.write_text(text, encoding="utf-8")
        return ToolResult(True, text, str(java_path), None, "java")

    monkeypatch.setattr("pipeline.get_manifest", fake_manifest)
    monkeypatch.setattr("pipeline.droidasc_available", lambda: True)
    monkeypatch.setattr("pipeline.decompile_class", fake_decompile)
    monkeypatch.setattr(
        "tools.native_decompiler.analyze_so",
            lambda so_path, java_refs=None: (["JNI_OnLoad"], "pdg", True, None),
    )

    sample = tmp_path / "app.apk"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("lib/arm64-v8a/libone.so", b"\x7fELF")
        archive.writestr("lib/arm64-v8a/libtwo.so", b"\x7fELF")
    bundle = build_case(sample, tmp_path / "workspace")

    assert {item.status for item in bundle.facts.components} == {"ok"}
    native = {item.name: item.status for item in bundle.facts.native_libs}
    assert native == {"libone.so": "ok", "libtwo.so": "ok"}


def test_cli_facts_only_prints_report_path(monkeypatch, tmp_path: Path, capsys):
    def fake_manifest(apk: Path, dest: Path) -> ToolResult:
        dest.write_text(MANIFEST, encoding="utf-8")
        return ToolResult(True, MANIFEST, str(dest), None, "manifest")

    monkeypatch.setattr("pipeline.get_manifest", fake_manifest)
    monkeypatch.setattr("pipeline.droidasc_available", lambda: False)
    sample = tmp_path / "app.apk"
    sample.write_bytes(b"not-a-zip")
    code = main(["analyze", str(sample), "--out", str(tmp_path / "workspace"), "--facts-only"])
    captured = capsys.readouterr()
    assert code == 0
    assert "report.json" in captured.out
    report_path = Path(captured.out.strip().splitlines()[-1])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["facts"]["package"] == "com.example.app"
    assert report["verdict"] is None


def test_missing_droidasc_is_a_result(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("tools.dex_decompiler.shutil.which", lambda name: None)
    result = get_manifest(tmp_path / "app.apk", tmp_path / "manifest.xml")
    assert result.ok is False
    assert result.error == "droidasc not on PATH"


def test_class_name_rejects_command_characters():
    assert validate_class_name("Lcom/example/Main;") == "Lcom/example/Main;"
    with pytest.raises(ValueError):
        validate_class_name("com.example.Main`id`")


def test_resolve_inside_rejects_escape(tmp_path: Path):
    inside = tmp_path / "evidence.txt"
    inside.write_text("ok", encoding="utf-8")
    assert resolve_inside(tmp_path, "evidence.txt") == inside.resolve()
    with pytest.raises(ValueError):
        resolve_inside(tmp_path, "../evidence.txt")


def test_case_server_exposes_sdk_tools(tmp_path: Path):
    server = build_case_server(tmp_path, None, "abc")
    assert server["type"] == "sdk"
    assert server["name"] == "case"


def test_find_refs_on_the_manifest_is_a_valid_call():
    import jsonschema

    call = {"kind": "permission", "path": "manifest.xml", "query": "android.permission.SEND_SMS"}
    jsonschema.validate(call, FIND_SCHEMA)
    assert manifest_request(call) is True
    assert manifest_request({"class_name": "AndroidManifest.xml", "kind": "string", "value": "INTERNET"}) is True
    assert manifest_request({"kind": "method", "value": "onCreate"}) is False
    text = """<uses-permission android:name="android.permission.SEND_SMS"/>
    <activity android:name=".Main" android:exported="true"/>
    <service android:name=".Worker" android:exported="false"/>"""
    found = search_manifest(text, "permission", "SEND_SMS")
    assert "SEND_SMS" in found
    assert "Worker" not in found
    listed = search_manifest(text, "permission", "")
    assert "SEND_SMS" in listed
    assert "no manifest line" in search_manifest(text, "component", "Missing")


def test_tools_accept_a_class_name_or_library_file_name(tmp_path: Path):
    import jsonschema

    jsonschema.validate({"file": "manifest.xml"}, READ_SCHEMA)
    jsonschema.validate({"class": "com.example.App"}, READ_SCHEMA)
    dex = tmp_path / "dex"
    dex.mkdir(parents=True)
    java = dex / "com.example.App.java"
    java.write_text("class App { void start() {} }", encoding="utf-8")
    (tmp_path / "ondemand").mkdir()
    (tmp_path / "ondemand" / "com.example.App.java").write_text("shorter", encoding="utf-8")
    assert resolve_case_file(tmp_path, "com.example.App") == java
    (tmp_path / "manifest.xml").write_text("<manifest/>", encoding="utf-8")
    assert resolve_case_file(tmp_path, "AndroidManifest.xml").name == "manifest.xml"
    native = tmp_path / "native" / "arm64-v8a"
    native.mkdir(parents=True)
    library = native / "libdemo.so"
    library.write_bytes(b"\x7fELF")
    assert resolve_library(tmp_path, "libdemo.so") == library
    assert resolve_library(tmp_path, "native/notes/libdemo.so.txt") == library
    assert class_from_reference("dex/com.example.App.java") == "com.example.App"
    assert class_from_reference("Lcom/example/App;") == "com.example.App"
    assert clean_symbol("Java_com_example_App_start(JNIEnv*, jobject)") == "Java_com_example_App_start"


def test_decompiled_java_and_pseudocode_are_returned_whole(tmp_path: Path):
    java = tmp_path / "dex" / "App.java"
    java.parent.mkdir(parents=True)
    body = "void onCreate() {}\n" * (PAGE_CHARS // 10)
    java.write_text(body, encoding="utf-8")
    shown = read_case_text(java, "dex/App.java")
    assert source_in_full("dex/App.java")
    assert body in shown
    assert "[truncated]" not in shown

    note = tmp_path / "native" / "notes" / "libdemo.so.txt"
    note.parent.mkdir(parents=True)
    pseudo = "int Crypt(void) { return 1; }\n" * 500
    note.write_text(pseudo, encoding="utf-8")
    shown = read_case_text(note, "native/notes/libdemo.so.txt")
    assert source_in_full("native/notes/libdemo.so.txt")
    assert pseudo in shown

    other = tmp_path / "crypto" / "report.txt"
    other.parent.mkdir(parents=True)
    report = "x" * (PAGE_CHARS + 100)
    other.write_text(report, encoding="utf-8")
    paged = read_case_text(other, "crypto/report.txt")
    assert source_in_full("crypto/report.txt") is False
    assert len(paged) < len(report)

    packed = _text(body, "abc", full=True)
    assert body in packed["content"][0]["text"]
    assert "[truncated]" not in packed["content"][0]["text"]


def test_verifier_fills_missing_ids_and_verdict_omits_rejected_text():
    findings = [
        Finding("f1", "supported behavior", [Evidence("dex/A.java", "A", "quote")], "low"),
        Finding("f2", "rejected secret behavior", [], "low"),
    ]
    aligned = align_verification(findings, {"findings": [{"id": "f1", "status": "supported", "note": "dex/A.java"}]})
    assert [item.status for item in aligned] == ["supported", "insufficient"]
    claimed = align_verification(
        [Finding("f9", "guessed behavior", [], "high")],
        {"findings": [{"id": "f9", "status": "supported", "note": "sure"}]},
    )
    assert claimed[0].status == "unsupported"
    opened = align_verification(
        [Finding("f3", "loads a class by reflection", [], "medium")],
        {"findings": [{"id": "f3", "status": "supported", "note": "Opened dex/com.example.App.java."}]},
    )
    assert opened[0].status == "supported"
    facts = SampleFacts(
        original=FileIdentity("a.apk", 1, "m", "s", "s"),
        container="apk",
        base_apk="a.apk",
        members=[],
        apks=[],
        package="com.example.app",
        version_name=None,
        version_code=None,
        app_label="Demo",
        app_label_ref=None,
        application_class=None,
        permissions=[],
        components=[],
        native_libs=[],
    )
    prompt = verdict_prompt(facts, [findings[0]], aligned, "abc")
    assert "supported behavior" in prompt
    assert "rejected secret behavior" not in prompt
    assert '"rejected_count": 1' in prompt


@pytest.mark.skipif(shutil.which("droidasc") is None, reason="droidasc missing")
def test_droidasc_invalid_apk_returns_error(tmp_path: Path):
    apk = tmp_path / "bad.apk"
    apk.write_bytes(b"not an apk")
    result = get_manifest(apk, tmp_path / "manifest.xml")
    assert result.ok is False
    assert result.error


@pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 missing")
def test_radare2_on_non_elf_does_not_raise(tmp_path: Path):
    from tools.native_decompiler import analyze_so

    library = tmp_path / "libdemo.so"
    library.write_bytes(b"not an elf")
    names, _report, produced, note = analyze_so(library)
    assert produced is False
    assert names == [] or note is None or note


def test_verifier_gets_the_analyst_tools(monkeypatch):
    from tools.mcp_server import ALLOWED_TOOLS

    seen = {}

    async def fake_run(_prompt, options):
        seen["tools"] = list(options.allowed_tools)
        seen["turns"] = options.max_turns
        return {"findings": []}

    monkeypatch.setattr("agents.verifier.run_structured", fake_run)
    from agents.verifier import run_verifier

    asyncio.run(run_verifier([], object(), nonce="abc", cwd=None))
    assert seen["tools"] == list(ALLOWED_TOOLS)
    assert "mcp__case__decompile_class" in seen["tools"]
    assert "mcp__case__decompile_native" in seen["tools"]
    assert "mcp__case__find_refs" in seen["tools"]
    assert "mcp__case__read_artifact" in seen["tools"]
    assert "mcp__case__unpack_stage1" in seen["tools"]
    assert seen["turns"] == 24


def test_droidasc_class_scan_uses_one_thread_and_manifest_does_not(monkeypatch, tmp_path: Path):
    seen = {"calls": []}

    def fake_run(args, **_kwargs):
        seen["calls"].append(list(args))

        class Proc:
            returncode = 1
            stdout = ""
            stderr = "no"

        return Proc()

    monkeypatch.setattr("tools.dex_decompiler.subprocess.run", fake_run)
    get_manifest(tmp_path / "a.apk", tmp_path / "manifest.xml")
    from tools.dex_decompiler import find_refs

    find_refs(tmp_path / "a.apk", "method", "onCreate")
    assert "--threads" not in seen["calls"][0]
    assert seen["calls"][1][seen["calls"][1].index("--threads") + 1] == "1"
    assert seen["calls"][1].index("--threads") < seen["calls"][1].index("method")


def test_every_manifest_class_is_analyzed(tmp_path: Path, monkeypatch):
    from schemas import Component, Evidence, FileIdentity, Finding, SampleFacts, Verification

    case = tmp_path / "case"
    (case / "dex").mkdir(parents=True)
    (case / "dex" / "Main.java").write_text("class Main { void onCreate() {} }", encoding="utf-8")
    (case / "dex" / "Worker.java").write_text("class Worker { void run() {} }", encoding="utf-8")
    identity = FileIdentity("app.apk", 3, "m", "s1", "s256")
    facts = SampleFacts(
        original=identity,
        container="apk",
        base_apk="app.apk",
        members=[],
        apks=[],
        package="com.example.app",
        version_name=None,
        version_code=None,
        app_label="Demo",
        app_label_ref=None,
        application_class="com.example.app.App",
        permissions=[],
        components=[
            Component("application", "com.example.app.App", None, [], "dex/Main.java", "ok"),
            Component("activity", "com.example.app.Main", True, [], "dex/Main.java", "ok"),
            Component("service", "com.example.app.Worker", False, [], "dex/Worker.java", "ok"),
        ],
        native_libs=[],
    )
    bundle = CaseBundle(case, facts, "pack", [], None, [])
    seen = {"classes": [], "correlate": None, "verifier": None}

    def fake_build(_sample, _out_root, _progress=None):
        return bundle

    async def fake_class(component, _case_dir, _base_apk, _nonce):
        seen["classes"].append((component.name, component.exported))
        path = "dex/Worker.java" if component.name.endswith("Worker") else "dex/Main.java"
        quote = "void run() {}" if component.name.endswith("Worker") else "void onCreate() {}"
        return [Finding("f1", f"{component.name} runs", [Evidence(path, component.name, quote)], "high")]

    async def fake_correlate(findings, _case_dir, _base_apk, _nonce, recovered=None):
        seen["correlate"] = [item.id for item in findings]
        return [
            Finding(
                "f1",
                "Main and Worker connect",
                [Evidence("dex/Main.java", "Main", "void onCreate() {}")],
                "high",
            )
        ]

    async def fake_verifier(findings, _server, *, nonce, cwd):
        seen["verifier"] = [item.behavior for item in findings]
        return [Verification(item.id, "supported", "dex/Main.java") for item in findings]

    async def fake_verdict(*_args, **_kwargs):
        from schemas import Verdict

        return Verdict("inconclusive", "unknown", "low", "Quoted.", [], False, "trojan")

    monkeypatch.setattr("pipeline.build_case", fake_build)
    monkeypatch.setattr("agents.analyst.run_class_analyst", fake_class)
    monkeypatch.setattr("agents.analyst.run_correlator", fake_correlate)
    monkeypatch.setattr("agents.verifier.run_verifier", fake_verifier)
    monkeypatch.setattr("agents.verdict.run_verdict", fake_verdict)

    report, _path = asyncio.run(analyze(tmp_path / "app.apk", tmp_path))
    assert seen["classes"] == [
        ("com.example.app.App", None),
        ("com.example.app.Main", True),
        ("com.example.app.Worker", False),
    ]
    assert seen["correlate"] == ["App-1", "Main-1", "Worker-1"]
    assert seen["verifier"] == ["Main and Worker connect"]
    assert [item.behavior for item in report.hypotheses] == ["Main and Worker connect"]
    assert report.errors == []
