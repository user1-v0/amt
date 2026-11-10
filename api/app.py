"""HTTP interface for the static analysis harness."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.chat import ask_case  # noqa: E402
from pipeline import analyze  # noqa: E402
from schemas import Evidence, Finding, present_verdict  # noqa: E402
from tools.mcp_server import resolve_inside  # noqa: E402
from tools.native_decompiler import (  # noqa: E402
    collect_java_native_refs,
    jni_methods_for_library,
    referenced_jni_report,
)
from utils.limits import truncate  # noqa: E402
from utils.snippets import evidence_snippet  # noqa: E402

ALLOWED_SUFFIXES = {".apk", ".xapk", ".apks"}
_SOURCE_SUFFIXES = {".java", ".kt", ".smali", ".js", ".xml"}
_HIDDEN_NAMES = {"case.json", "report.json", "findings.json", "verification.json", "evidence.txt"}
_VIEW_CHARS = 200_000
logger = logging.getLogger("mr-amt")


def form_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(workspace: Path) -> FastAPI:
    workspace = workspace.resolve()
    uploads = workspace / "uploads"
    jobs_dir = workspace / "jobs"
    uploads.mkdir(parents=True, exist_ok=True)
    jobs_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="mr-amt")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def job_path(job_id: str) -> Path:
        return jobs_dir / f"{job_id}.json"

    tasks: set[asyncio.Task] = set()

    def write_job(job: dict) -> None:
        path = job_path(job["id"])
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(job), encoding="utf-8")
        temporary.replace(path)

    def read_job(job_id: str) -> dict:
        path = job_path(job_id)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="analysis not found")
        return json.loads(path.read_text(encoding="utf-8"))

    async def run_job(job_id: str) -> None:
        job = read_job(job_id)
        job["status"] = "running"
        job["stage"] = "unpacking"
        write_job(job)

        def progress(stage: str, bundle=None, hypotheses=None, verification=None, payloads=None) -> None:
            current = read_job(job_id)
            current["status"] = "running"
            current["stage"] = stage
            if payloads is not None:
                current["payloads"] = payloads
            report = current.get("report")
            if bundle is not None:
                current["case_dir"] = str(bundle.case_dir)
                report = {
                    "facts": asdict(bundle.facts),
                    "hypotheses": [],
                    "verification": [],
                    "verdict": None,
                    "artifact_paths": bundle.artifact_paths,
                    "errors": [],
                }
            if isinstance(report, dict):
                if hypotheses is not None:
                    report["hypotheses"] = [asdict(item) for item in hypotheses]
                if verification is not None:
                    report["verification"] = [asdict(item) for item in verification]
                current["report"] = report
            write_job(current)

        try:
            report, report_path = await analyze(
                Path(job["sample_path"]),
                workspace,
                run_agents=not job["facts_only"],
                progress=progress,
            )
        except Exception as exc:
            logger.exception("analysis %s failed", job_id)
            failed = read_job(job_id)
            failed["status"] = "error"
            failed["stage"] = "error"
            failed["error"] = str(exc)
            write_job(failed)
            return
        finished = read_job(job_id)
        finished["status"] = "done"
        finished["stage"] = "done"
        finished["report_path"] = str(report_path)
        finished["report"] = report.to_dict()
        finished["case_dir"] = str(report_path.parent)
        write_job(finished)

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True}

    @app.get("/api/analyses")
    def list_analyses() -> list[dict]:
        jobs = []
        for path in jobs_dir.glob("*.json"):
            job = json.loads(path.read_text(encoding="utf-8"))
            jobs.append(_summary(job))
        jobs.sort(key=lambda item: item["created_at"], reverse=True)
        return jobs

    @app.get("/api/analyses/{job_id}")
    def get_analysis(job_id: str) -> dict:
        return _with_snippets(read_job(job_id), workspace)

    @app.post("/api/analyses", status_code=202)
    async def start_analysis(
        background: BackgroundTasks,
        file: UploadFile,
        facts_only: str = Form("false"),
    ) -> dict:
        filename = Path(file.filename or "").name
        suffix = Path(filename).suffix.lower()
        if suffix not in ALLOWED_SUFFIXES:
            raise HTTPException(status_code=400, detail="upload an apk, xapk, or apks file")
        job_id = uuid.uuid4().hex
        sample_dir = uploads / job_id
        sample_dir.mkdir(parents=True)
        sample_path = sample_dir / filename
        with sample_path.open("wb") as handle:
            while chunk := await file.read(1024 * 1024):
                handle.write(chunk)
        job = {
            "id": job_id,
            "filename": filename,
            "facts_only": form_bool(facts_only),
            "status": "queued",
            "stage": "queued",
            "error": None,
            "sample_path": str(sample_path),
            "report_path": None,
            "report": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        write_job(job)

        async def launch() -> None:
            task = asyncio.create_task(run_job(job_id))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                return

        background.add_task(launch)
        return _summary(job)

    @app.post("/api/analyses/{job_id}/reanalyze", status_code=202)
    async def reanalyze(job_id: str, background: BackgroundTasks) -> dict:
        original = read_job(job_id)
        sample = _uploaded_sample(original, workspace)
        if _sample_is_running(sample, jobs_dir):
            raise HTTPException(status_code=409, detail="this sample is already being analyzed")
        new_id = uuid.uuid4().hex
        job = {
            "id": new_id,
            "filename": original.get("filename") or sample.name,
            "facts_only": False,
            "status": "queued",
            "stage": "queued",
            "error": None,
            "sample_path": str(sample),
            "report_path": None,
            "report": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        write_job(job)

        async def launch() -> None:
            task = asyncio.create_task(run_job(new_id))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                return

        background.add_task(launch)
        return _summary(job)

    @app.get("/api/analyses/{job_id}/files")
    def list_source(job_id: str) -> dict:
        case_dir = _require_case(read_job(job_id), workspace)
        files = []
        for path in sorted(case_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(case_dir).as_posix()
            if not _viewable(relative):
                continue
            files.append({"path": relative, "kind": _source_kind(relative), "size": path.stat().st_size})
        return {"files": files}

    @app.get("/api/analyses/{job_id}/file")
    def read_source(job_id: str, path: str = Query(min_length=1)) -> dict:
        case_dir = _require_case(read_job(job_id), workspace)
        if not _viewable(path):
            raise HTTPException(status_code=400, detail="this file is not shown in the viewer")
        try:
            target = resolve_inside(case_dir, path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not target.is_file():
            raise HTTPException(status_code=404, detail="file not found")
        data = target.read_bytes()
        if b"\x00" in data[:512]:
            raise HTTPException(status_code=400, detail="file is binary")
        text = data.decode("utf-8", errors="replace")
        if Path(path).parts[:2] == ("native", "notes"):
            text = referenced_jni_report(text, collect_java_native_refs([case_dir / "dex"]))
        shown, truncated = truncate(text, _VIEW_CHARS)
        if shown.endswith("\n...[truncated]"):
            shown = shown[: -len("\n...[truncated]")]
        return {
            "path": path,
            "kind": _source_kind(path),
            "text": shown,
            "truncated": truncated,
            "length": len(text),
        }

    @app.post("/api/analyses/{job_id}/chat")
    async def chat(job_id: str, body: ChatIn) -> dict:
        message = body.message.strip()
        if not message:
            raise HTTPException(status_code=400, detail="message is empty")
        job = read_job(job_id)
        case_dir = _case_dir(job, workspace)
        try:
            result = await ask_case(
                message[:2000],
                _chat_context(job, workspace),
                case_dir=case_dir,
                base_apk=_base_apk(case_dir, job),
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)[:300]) from exc
        actions = [str(item).strip() for item in result.get("actions") or [] if str(item).strip()][:3]
        return {"reply": str(result.get("reply") or "").strip(), "actions": actions}

    return app


class ChatIn(BaseModel):
    message: str


def _uploaded_sample(job: dict, workspace: Path) -> Path:
    raw = str(job.get("sample_path") or "")
    uploads = (workspace / "uploads").resolve()
    if not raw:
        raise HTTPException(status_code=400, detail="the uploaded sample is no longer available")
    try:
        path = Path(raw).resolve()
    except OSError as exc:
        raise HTTPException(status_code=400, detail="the uploaded sample is no longer available") from exc
    if uploads not in path.parents or not path.is_file():
        raise HTTPException(status_code=400, detail="the uploaded sample is no longer available")
    return path


def _sample_is_running(sample: Path, jobs_dir: Path) -> bool:
    for path in jobs_dir.glob("*.json"):
        job = json.loads(path.read_text(encoding="utf-8"))
        stored = str(job.get("sample_path") or "")
        if not stored or job.get("status") not in {"queued", "running"}:
            continue
        try:
            same = Path(stored).resolve() == sample
        except OSError:
            same = False
        if same:
            return True
    return False


def _require_case(job: dict, workspace: Path) -> Path:
    case_dir = _case_dir(job, workspace)
    if case_dir is None:
        raise HTTPException(status_code=404, detail="decompiled files are not ready")
    return case_dir


def _viewable(relative: str) -> bool:
    path = Path(relative)
    if not relative or path.name in _HIDDEN_NAMES or path.suffix.lower() not in _SOURCE_SUFFIXES | {".txt"}:
        return False
    if path.suffix.lower() in _SOURCE_SUFFIXES:
        return True
    parts = path.parts
    return parts[:2] == ("native", "notes") or bool(parts) and parts[0] in {"stage1", "crypto"}


def _source_kind(relative: str) -> str:
    parts = Path(relative).parts
    if not parts:
        return "other"
    if parts[0] == "native":
        return "native"
    if parts[0] == "dex":
        return "manifest"
    if parts[0] == "ondemand":
        return "dex"
    if parts[0] == "stage1":
        return "stage1"
    if parts[0] == "crypto":
        return "crypto"
    if parts[0] == "framework":
        return "framework"
    if Path(relative).name == "manifest.xml":
        return "manifest"
    return "other"


def _case_dir(job: dict, workspace: Path) -> Path | None:
    for raw in (job.get("case_dir"), job.get("report_path")):
        if not raw:
            continue
        path = Path(raw)
        if raw == job.get("report_path"):
            path = path.parent
        if path.is_dir():
            return path
        mounted = workspace / path.name
        if mounted.is_dir():
            return mounted
    return None


def _with_snippets(job: dict, workspace: Path) -> dict:
    report = present_verdict(job.get("report"))
    if not isinstance(report, dict):
        return job
    case_dir = _case_dir(job, workspace)
    hypotheses = []
    for finding in report.get("hypotheses") or []:
        if not isinstance(finding, dict):
            hypotheses.append(finding)
            continue
        copied = dict(finding)
        evidence = []
        for item in finding.get("evidence") or []:
            if not isinstance(item, dict):
                evidence.append(item)
                continue
            enriched = dict(item)
            enriched.update(
                evidence_snippet(case_dir, str(item.get("path") or ""), str(item.get("quote") or ""))
            )
            evidence.append(enriched)
        copied["evidence"] = evidence
        hypotheses.append(copied)
    facts = dict(report.get("facts") or {})
    libraries = []
    for lib in facts.get("native_libs") or []:
        if not isinstance(lib, dict):
            libraries.append(lib)
            continue
        copied = dict(lib)
        if "jni_methods" not in copied:
            copied["jni_methods"] = jni_methods_for_library(case_dir, str(copied.get("name") or ""))
        libraries.append(copied)
    facts["native_libs"] = libraries
    shown = dict(job)
    shown["report"] = dict(report)
    shown["report"]["facts"] = facts
    shown["report"]["hypotheses"] = hypotheses
    return shown


def _chat_context(job: dict, workspace: Path) -> str:
    report = job.get("report") or {}
    facts = report.get("facts") or {}
    verdict = report.get("verdict") or {}
    lines = [
        f"file: {job.get('filename') or ''}",
        f"package: {facts.get('package') or ''}",
        f"type: {verdict.get('malware_type') or ''}",
        f"family: {verdict.get('family') or ''}",
        f"summary: {verdict.get('summary') or ''}",
    ]
    for item in report.get("hypotheses") or []:
        if not isinstance(item, dict):
            continue
        paths = ", ".join(
            str(evidence.get("path") or "")
            for evidence in item.get("evidence") or []
            if isinstance(evidence, dict)
        )
        lines.append(f"{item.get('id')}: {item.get('behavior')} [{paths}]")
    case_dir = _case_dir(job, workspace)
    if case_dir is not None:
        files = [
            path.relative_to(case_dir).as_posix()
            for path in sorted(case_dir.rglob("*"))
            if path.is_file() and _viewable(path.relative_to(case_dir).as_posix())
        ]
        if files:
            lines.append("files:")
            lines.extend(f"- {item}" for item in files[:80])
        crypto = case_dir / "crypto" / "report.txt"
        if crypto.is_file():
            lines.append(crypto.read_text(encoding="utf-8", errors="replace")[:2000])
    return "\n".join(lines)


def _base_apk(case_dir: Path | None, job: dict) -> Path | None:
    if case_dir is None:
        return None
    facts = (job.get("report") or {}).get("facts") or {}
    name = str(facts.get("base_apk") or "")
    if name and "/" not in name and not name.startswith("."):
        candidate = case_dir / "apks" / name
        if candidate.is_file():
            return candidate
    apk_dir = case_dir / "apks"
    if not apk_dir.is_dir():
        return None
    found = sorted(apk_dir.glob("*.apk"))
    return found[0] if found else None


def _summary(job: dict) -> dict:
    report = present_verdict(job.get("report") or {})
    facts = report.get("facts") or {}
    verdict = report.get("verdict") or {}
    return {
        "id": job["id"],
        "filename": job["filename"],
        "facts_only": job["facts_only"],
        "status": job["status"],
        "error": job.get("error"),
        "created_at": job["created_at"],
        "package": facts.get("package"),
        "verdict": verdict.get("verdict"),
        "malware_type": verdict.get("malware_type"),
        "family": verdict.get("family"),
    }


load_dotenv(ROOT / ".env")
app = create_app(ROOT / "workspace")
