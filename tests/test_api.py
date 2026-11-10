import asyncio
import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from schemas import FileIdentity, Report, SampleFacts


def _report() -> Report:
    identity = FileIdentity("app.apk", 4, "m", "s", "abc")
    return Report(
        facts=SampleFacts(
            original=identity,
            container="apk",
            base_apk="app.apk",
            members=[],
            apks=[identity],
            package="com.example.app",
            version_name="1",
            version_code="1",
            app_label="Demo",
            app_label_ref=None,
            application_class=None,
            permissions=["android.permission.INTERNET"],
            components=[],
            native_libs=[],
        ),
        hypotheses=[],
        verification=[],
        verdict=None,
        artifact_paths=[],
    )


def test_source_viewer_reads_decompiled_text_and_hides_binaries(tmp_path: Path):
    case = tmp_path / "abc"
    (case / "dex").mkdir(parents=True)
    (case / "dex" / "com.example.App.java").write_text(
        "package com.example;\npublic class App {\n"
        "  public native void start();\n  void run() { start(); }\n}\n",
        encoding="utf-8",
    )
    (case / "manifest.xml").write_text("<manifest package=\"com.example\"/>", encoding="utf-8")
    (case / "native" / "notes").mkdir(parents=True)
    (case / "native" / "notes" / "libdemo.so.txt").write_text(
        "## Java_com_example_App_start\nint start(void) { return 1; }\n\n"
        "## decodePacket\nint decode(void) { return 2; }\n",
        encoding="utf-8",
    )
    (case / "native" / "arm64-v8a").mkdir(parents=True)
    (case / "native" / "arm64-v8a" / "libdemo.so").write_bytes(b"\x7fELF\x00bin")
    (case / "secret.txt").write_text("hidden", encoding="utf-8")
    job_id = "job1"
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / f"{job_id}.json").write_text(
        json.dumps(
            {
                "id": job_id,
                "filename": "app.apk",
                "facts_only": True,
                "status": "done",
                "error": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "case_dir": str(case),
                "report": _report().to_dict(),
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    listed = client.get(f"/api/analyses/{job_id}/files")
    assert listed.status_code == 200
    files = listed.json()["files"]
    paths = [item["path"] for item in files]
    assert paths == ["dex/com.example.App.java", "manifest.xml", "native/notes/libdemo.so.txt"]
    kinds = {item["path"]: item["kind"] for item in files}
    assert kinds["dex/com.example.App.java"] == "manifest"
    assert kinds["manifest.xml"] == "manifest"
    opened = client.get(f"/api/analyses/{job_id}/file", params={"path": "dex/com.example.App.java"})
    assert opened.status_code == 200
    assert "start" in opened.json()["text"]
    native = client.get(f"/api/analyses/{job_id}/file", params={"path": "native/notes/libdemo.so.txt"})
    assert native.status_code == 200
    assert "return 1" in native.json()["text"]
    assert "decodePacket" not in native.json()["text"]
    assert client.get(f"/api/analyses/{job_id}/file", params={"path": "../secret.txt"}).status_code == 400
    assert client.get(f"/api/analyses/{job_id}/file", params={"path": "native/arm64-v8a/libdemo.so"}).status_code == 400


def test_chat_answers_from_the_case(tmp_path: Path, monkeypatch):
    async def fake_ask(message: str, context: str, **kwargs) -> dict:
        assert "dropper" in context
        assert message == "What does the app load?"
        assert kwargs.get("case_dir") is None
        return {"reply": "Open dex/Loader.java.", "actions": ["Open the native note"]}

    monkeypatch.setattr("api.app.ask_case", fake_ask)
    job_id = "chat1"
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    report = _report().to_dict()
    report["verdict"] = {
        "verdict": "malicious",
        "family": "dropper",
        "confidence": "medium",
        "summary": "It loads another component.",
        "supporting_finding_ids": [],
        "malicious": True,
        "malware_type": "trojan",
    }
    (jobs / f"{job_id}.json").write_text(
        json.dumps(
            {
                "id": job_id,
                "filename": "app.apk",
                "facts_only": False,
                "status": "done",
                "error": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "report": report,
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    response = client.post(f"/api/analyses/{job_id}/chat", json={"message": "What does the app load?"})
    assert response.status_code == 200
    assert response.json()["reply"] == "Open dex/Loader.java."
    assert response.json()["actions"] == ["Open the native note"]


def test_chat_can_open_files_in_the_case(tmp_path: Path, monkeypatch):
    seen: dict = {}

    async def fake_run(prompt: str, options) -> dict:
        seen["tools"] = list(options.allowed_tools)
        seen["turns"] = options.max_turns
        assert "dex/App.java" in prompt
        return {"reply": "dex/App.java calls start().", "actions": []}

    monkeypatch.setattr("agents.chat.run_structured", fake_run)
    case = tmp_path / "case"
    (case / "dex").mkdir(parents=True)
    (case / "dex" / "App.java").write_text("void start();", encoding="utf-8")
    from agents.chat import ask_case

    result = asyncio.run(ask_case("What does App do?", "files:\n- dex/App.java", case_dir=case))
    assert "mcp__case__read_artifact" in seen["tools"]
    assert "mcp__case__decompile_class" in seen["tools"]
    assert seen["turns"] == 8
    assert result["reply"] == "dex/App.java calls start()."


def test_chat_passes_the_case_directory(tmp_path: Path, monkeypatch):
    seen: dict = {}

    async def fake_ask(message: str, context: str, **kwargs) -> dict:
        seen["case"] = kwargs.get("case_dir")
        seen["apk"] = kwargs.get("base_apk")
        assert "dex/App.java" in context
        assert message == "Open the class"
        return {"reply": "opened", "actions": []}

    monkeypatch.setattr("api.app.ask_case", fake_ask)
    case = tmp_path / "abc"
    (case / "dex").mkdir(parents=True)
    (case / "dex" / "App.java").write_text("class App {}", encoding="utf-8")
    (case / "apks").mkdir()
    (case / "apks" / "app.apk").write_bytes(b"apk")
    job_id = "chat2"
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    report = _report().to_dict()
    (jobs / f"{job_id}.json").write_text(
        json.dumps(
            {
                "id": job_id,
                "filename": "app.apk",
                "facts_only": True,
                "status": "done",
                "error": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "case_dir": str(case),
                "report": report,
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    response = client.post(f"/api/analyses/{job_id}/chat", json={"message": "Open the class"})
    assert response.status_code == 200
    assert seen["case"] == case
    assert seen["apk"] == case / "apks" / "app.apk"
    assert response.json()["reply"] == "opened"


def test_upload_rejects_unknown_type(tmp_path: Path):
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/api/analyses",
        files={"file": ("notes.txt", b"hello", "text/plain")},
        data={"facts_only": "true"},
    )
    assert response.status_code == 400


def test_facts_only_job_completes(tmp_path: Path, monkeypatch):
    async def fake_analyze(sample: Path, out_root: Path, *, run_agents: bool = True, progress=None):
        assert run_agents is False
        if progress is not None:
            progress("decompiled")
        report = _report()
        report_path = out_root / "abc" / "report.json"
        report_path.parent.mkdir()
        report_path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
        return report, report_path

    monkeypatch.setattr("api.app.analyze", fake_analyze)
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/api/analyses",
        files={"file": ("app.apk", b"apk", "application/vnd.android.package-archive")},
        data={"facts_only": "true"},
    )
    assert response.status_code == 202
    job_id = response.json()["id"]
    stored = client.get(f"/api/analyses/{job_id}")
    assert stored.status_code == 200
    body = stored.json()
    assert body["status"] == "done"
    assert body["report"]["facts"]["package"] == "com.example.app"
    listed = client.get("/api/analyses").json()
    assert listed[0]["package"] == "com.example.app"


def test_reanalyze_starts_a_full_review_of_the_same_file(tmp_path: Path, monkeypatch):
    seen: dict[str, object] = {}

    async def fake_analyze(sample: Path, out_root: Path, *, run_agents: bool = True, progress=None):
        seen["sample"] = sample
        seen["run_agents"] = run_agents
        report = _report()
        report_path = out_root / "abc" / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("{}", encoding="utf-8")
        return report, report_path

    original = "job1"
    sample = tmp_path / "uploads" / original / "app.apk"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"apk")
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / f"{original}.json").write_text(
        json.dumps(
            {
                "id": original,
                "filename": "app.apk",
                "facts_only": True,
                "status": "done",
                "error": None,
                "sample_path": str(sample),
                "created_at": "2026-01-01T00:00:00+00:00",
                "report": _report().to_dict(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("api.app.analyze", fake_analyze)
    client = TestClient(create_app(tmp_path))
    response = client.post(f"/api/analyses/{original}/reanalyze")
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["id"] != original
    stored = client.get(f"/api/analyses/{body['id']}")
    assert stored.status_code == 200
    assert stored.json()["status"] == "done"
    assert stored.json()["facts_only"] is False
    assert seen["sample"] == sample
    assert seen["run_agents"] is True
    assert client.get(f"/api/analyses/{original}").json()["status"] == "done"


def test_reanalyze_waits_while_that_sample_is_running(tmp_path: Path):
    sample = tmp_path / "uploads" / "job1" / "app.apk"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"apk")
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / "job1.json").write_text(
        json.dumps(
            {
                "id": "job1",
                "filename": "app.apk",
                "facts_only": False,
                "status": "running",
                "sample_path": str(sample),
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    response = client.post("/api/analyses/job1/reanalyze")
    assert response.status_code == 409
    assert response.json()["detail"] == "this sample is already being analyzed"


def test_reanalyze_rejects_a_missing_upload(tmp_path: Path):
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / "job1.json").write_text(
        json.dumps(
            {
                "id": "job1",
                "filename": "app.apk",
                "facts_only": False,
                "status": "done",
                "sample_path": str(tmp_path / "uploads" / "job1" / "gone.apk"),
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    response = client.post("/api/analyses/job1/reanalyze")
    assert response.status_code == 400
    assert response.json()["detail"] == "the uploaded sample is no longer available"


def test_full_review_is_the_default(tmp_path: Path, monkeypatch):
    seen: dict[str, bool] = {}

    async def fake_analyze(sample: Path, out_root: Path, *, run_agents: bool = True, progress=None):
        seen["run_agents"] = run_agents
        report = _report()
        report_path = out_root / "abc" / "report.json"
        report_path.parent.mkdir()
        report_path.write_text("{}", encoding="utf-8")
        return report, report_path

    monkeypatch.setattr("api.app.analyze", fake_analyze)
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/api/analyses",
        files={"file": ("app.apk", b"apk", "application/vnd.android.package-archive")},
        data={"facts_only": "false"},
    )
    assert response.status_code == 202
    assert seen["run_agents"] is True
