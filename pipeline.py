"""Fixed-order static analysis. Agents run only after the case is on disk."""

from __future__ import annotations

import asyncio
import json
import secrets
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from schemas import Component, Payload, Report, SampleFacts, Verification, enforce_verdict
from tools.crypto_trace import render_crypto_report, trace_case
from tools.dex_decompiler import (
    class_filename,
    decompile_class,
    droidasc_available,
    get_manifest,
)
from tools.frameworks import unpack_framework
from tools.metadata import file_fingerprints, file_identity, parse_manifest_xml, signature_fingerprints
from tools.native_decompiler import collect_native
from tools.stage1 import first_stage_classes, pack_reason, unpack_stage1
from tools.unpack import unpack_sample
from utils.limits import EXCERPT_CHARS, MAX_PACK_CHARS, truncate


@dataclass
class CaseBundle:
    case_dir: Path
    facts: SampleFacts
    pack_text: str
    artifact_paths: list[str]
    base_apk: Path | None
    apks: list[Path]


def list_artifacts(case_dir: Path) -> list[str]:
    return sorted(
        path.relative_to(case_dir).as_posix()
        for path in case_dir.rglob("*")
        if path.is_file()
    )


def render_pack(facts: SampleFacts, excerpts: list[tuple[str, str]]) -> str:
    lines = [
        f"container: {facts.container}",
        f"framework: {facts.framework}",
        f"file: {facts.original.name}",
        f"size: {facts.original.size}",
        f"md5: {facts.original.md5}",
        f"sha1: {facts.original.sha1}",
        f"sha256: {facts.original.sha256}",
        "fingerprints:",
        *[f"- {item.kind} {item.name} {item.sha256}" for item in facts.fingerprints],
        f"package: {facts.package or ''}",
        f"version_name: {facts.version_name or ''}",
        f"version_code: {facts.version_code or ''}",
        f"app_label: {facts.app_label or ''}",
        f"app_label_ref: {facts.app_label_ref or ''}",
        f"application: {facts.application_class or ''}",
        "permissions:",
        *[f"- {permission}" for permission in facts.permissions],
        "decompiled_classes:",
    ]
    decompiled = [item for item in facts.components if item.status != "skipped"]
    skipped = len(facts.components) - len(decompiled)
    lines.append(f"skipped_classes: {skipped}")
    for component in decompiled:
        actions = ",".join(component.actions)
        lines.append(
            f"- {component.kind} {component.name} exported={component.exported} "
            f"actions={actions} status={component.status} path={component.decompile_path or ''}"
        )
    lines.append("decompiled_native:")
    shown_native = [item for item in facts.native_libs if item.status != "skipped"]
    lines.append(f"skipped_native: {len(facts.native_libs) - len(shown_native)}")
    for lib in shown_native:
        functions = ",".join(lib.functions[:15])
        lines.append(
            f"- {lib.path} abi={lib.abi} status={lib.status} "
            f"pseudocode={lib.pseudocode} note={lib.note or ''} functions={functions}"
        )
    if facts.framework_files:
        lines.append("framework_files:")
        lines.extend(f"- {path}" for path in facts.framework_files)
    if facts.stage_notes:
        lines.append("notes:")
        lines.extend(f"- {note}" for note in facts.stage_notes)
    lines.append("excerpts:")
    text = "\n".join(lines) + "\n"
    for path, excerpt in excerpts:
        block = f"\n### {path}\n{excerpt}\n"
        if len(text) + len(block) > MAX_PACK_CHARS:
            text += "\n...[pack truncated]\n"
            break
        text += block
    text, _ = truncate(text, MAX_PACK_CHARS)
    return text


def _decompile_components(
    base_apk: Path | None,
    components: list[Component],
    class_names: list[str],
    dex_dir: Path,
    notes: list[str],
) -> list[tuple[str, str]]:
    excerpts: list[tuple[str, str]] = []
    if not class_names:
        return excerpts
    if base_apk is None or not droidasc_available():
        reason = "no base APK" if base_apk is None else "droidasc not on PATH"
        notes.append(f"dex decompilation skipped: {reason}")
        for component in components:
            if component.name in class_names:
                component.status = "skipped"
                component.error = reason
        return excerpts

    by_name = {component.name: component for component in components}
    for class_name in class_names:
        java_path = dex_dir / class_filename(class_name, "java")
        smali_path = dex_dir / class_filename(class_name, "smali")
        try:
            result = decompile_class(base_apk, class_name, java_path, smali_path)
        except ValueError as exc:
            result_ok = False
            error = str(exc)
            rel = None
            text = ""
            backend_path = None
        else:
            result_ok = result.ok
            error = result.error
            text = result.text
            backend_path = result.path
            rel = None
        component = by_name.get(class_name)
        if result_ok and backend_path is not None:
            rel = Path(backend_path).resolve().relative_to(dex_dir.parent.resolve()).as_posix()
            if component is not None:
                component.status = "ok"
                component.decompile_path = rel
                component.error = None
            excerpts.append((rel, text[:EXCERPT_CHARS]))
        elif component is not None:
            component.status = "error"
            component.error = error
        else:
            notes.append(f"{class_name}: {error}")
    return excerpts


def build_case(sample: Path, out_root: Path, progress=None) -> CaseBundle:
    def step(stage: str, payloads=None) -> None:
        if progress is not None:
            progress(stage, payloads=payloads)

    step("unpacking")
    sample = Path(sample)
    original = file_identity(sample)
    case_dir = Path(out_root) / original.sha256
    case_dir.mkdir(parents=True, exist_ok=True)
    unpacked = unpack_sample(sample, case_dir, original)
    notes: list[str] = []
    package = version_name = version_code = None
    app_label = app_label_ref = application_class = None
    permissions: list[str] = []
    components: list[Component] = []

    if unpacked.base_apk is None:
        notes.append("no base APK found")
    else:
        manifest_path = case_dir / "manifest.xml"
        manifest = get_manifest(unpacked.base_apk, manifest_path)
        if not manifest.ok:
            notes.append(f"manifest skipped: {manifest.error}")
        else:
            try:
                parsed = parse_manifest_xml(manifest.text)
            except (ET.ParseError, ValueError) as exc:
                notes.append(f"manifest parse failed: {exc}")
            else:
                package = parsed.package
                version_name = parsed.version_name
                version_code = parsed.version_code
                app_label = parsed.app_label
                app_label_ref = parsed.app_label_ref
                application_class = parsed.application_class
                permissions = parsed.permissions
                components = parsed.components

    if application_class and application_class not in {item.name for item in components}:
        components.insert(
            0,
            Component(kind="application", name=application_class, exported=None),
        )
    requested: list[str] = []
    seen: set[str] = set()
    # Every class named on a manifest component is decompiled, exported or not.
    for name in [application_class or "", *[item.name for item in components]]:
        if name and name not in seen:
            seen.add(name)
            requested.append(name)

    step("decompiling")
    excerpts = _decompile_components(
        unpacked.base_apk,
        components,
        requested,
        case_dir / "dex",
        notes,
    )
    decompiled_ok = sum(1 for component in components if component.status == "ok")
    if components:
        notes.append(f"decompiled {decompiled_ok} of {len(components)} classes")
    for component in components:
        if component.status == "pending":
            component.status = "error"
            component.error = "not decompiled"
    step("framework")
    framework = unpack_framework(unpacked.apks, case_dir)
    notes.extend(framework.notes)
    excerpts.extend(framework.excerpts)
    step("native")
    native_libs, native_notes = collect_native(
        unpacked.apks,
        case_dir / "native",
        framework.prefer_libs,
        java_roots=[case_dir / "dex"],
    )
    notes.extend(native_notes)
    if not native_libs and not native_notes:
        notes.append("no native libraries")
    decoded: list[Payload] = []
    reason = pack_reason(
        unpacked.base_apk,
        application_class,
        "\n".join(text for _path, text in excerpts),
    )
    if reason and unpacked.base_apk is not None:
        stage_dir = case_dir / "stage1"
        unpacked_stage = unpack_stage1(unpacked.base_apk, stage_dir)
        report = unpacked_stage.report
        (stage_dir / "report.txt").write_text(report, encoding="utf-8")
        decoded = [
            Payload(item.name, item.kind, item.via, item.size, item.detail)
            for item in unpacked_stage.payloads
        ]
        notes.append(f"unpacked the first stage only ({reason})")
        excerpts.append(("stage1/report.txt", report[:EXCERPT_CHARS]))
        step(
            "payloads",
            {"files": [asdict(item) for item in decoded], "note": "" if decoded else report},
        )
        for container, class_name in first_stage_classes(stage_dir):
            java_path = stage_dir / "src" / class_filename(class_name, "java")
            smali_path = stage_dir / "src" / class_filename(class_name, "smali")
            result = decompile_class(container, class_name, java_path, smali_path)
            if result.ok and result.path:
                rel = Path(result.path).resolve().relative_to(case_dir.resolve()).as_posix()
                excerpts.append((rel, result.text[:EXCERPT_CHARS]))
            elif result.error:
                notes.append(f"stage-1 {class_name}: {result.error}")
    notes_dir = case_dir / "native" / "notes"
    if notes_dir.is_dir():
        for path in sorted(notes_dir.glob("*.txt")):
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                excerpts.append((path.relative_to(case_dir).as_posix(), text[:EXCERPT_CHARS]))
    crypto_hits = trace_case(case_dir)
    if crypto_hits:
        crypto_text = render_crypto_report(crypto_hits)
        crypto_path = case_dir / "crypto" / "report.txt"
        crypto_path.parent.mkdir(parents=True, exist_ok=True)
        crypto_path.write_text(crypto_text, encoding="utf-8")
        excerpts.append(("crypto/report.txt", crypto_text[:EXCERPT_CHARS]))
        recovered = [hit for hit in crypto_hits if hit.kind]
        if recovered:
            notes.append(f"traced {len(recovered)} static payload(s) from literals in source")
        for hit in recovered:
            decoded.append(
                Payload(Path(hit.path).name, hit.kind, hit.via, hit.size, hit.detail[:500])
            )
        step(
            "payloads",
            {"files": [asdict(item) for item in decoded], "note": "" if decoded else crypto_text[:500]},
        )

    facts = SampleFacts(
        original=original,
        container=unpacked.container,
        base_apk=None if unpacked.base_apk is None else unpacked.base_apk.name,
        members=unpacked.members,
        apks=[file_identity(path) for path in unpacked.apks],
        package=package,
        version_name=version_name,
        version_code=version_code,
        app_label=app_label,
        app_label_ref=app_label_ref,
        application_class=application_class,
        permissions=permissions,
        components=components,
        native_libs=native_libs,
        stage_notes=notes,
        framework=framework.name,
        framework_files=framework.files,
        fingerprints=[
            *file_fingerprints(original),
            *(signature_fingerprints(unpacked.base_apk) if unpacked.base_apk else []),
        ],
        payloads=decoded,
    )
    pack_text = render_pack(facts, excerpts)
    (case_dir / "evidence.txt").write_text(pack_text, encoding="utf-8")
    artifacts = list_artifacts(case_dir)
    if "case.json" not in artifacts:
        artifacts.append("case.json")
        artifacts.sort()
    (case_dir / "case.json").write_text(
        json.dumps({"facts": asdict(facts), "artifacts": artifacts}, indent=2),
        encoding="utf-8",
    )
    return CaseBundle(
        case_dir=case_dir,
        facts=facts,
        pack_text=pack_text,
        artifact_paths=artifacts,
        base_apk=unpacked.base_apk,
        apks=unpacked.apks,
    )


async def analyze(
    sample: Path,
    out_root: Path,
    *,
    run_agents: bool = True,
    progress=None,
) -> tuple[Report, Path]:
    def step(
        stage: str,
        bundle: CaseBundle | None = None,
        hypotheses: list | None = None,
        verification: list | None = None,
        payloads=None,
    ) -> None:
        if progress is not None:
            progress(stage, bundle, hypotheses, verification, payloads)

    bundle = await asyncio.to_thread(build_case, sample, out_root, step)
    step("decompiled", bundle)
    hypotheses = []
    verification = []
    verdict = None
    errors: list[str] = []
    if run_agents:
        from agents.analyst import (
            findings_for_verifier,
            gather_class_findings,
            grounded_findings,
            run_correlator,
        )
        from agents.verifier import run_verifier
        from agents.verdict import run_verdict
        from tools.mcp_server import build_case_server

        nonce = secrets.token_hex(8)
        step("analyst")
        class_findings, class_errors = await gather_class_findings(
            bundle.facts.components,
            bundle.case_dir,
            bundle.base_apk,
            nonce,
        )
        errors.extend(class_errors)
        if bundle.facts.components and not class_findings and class_errors:
            pass
        else:
            step("correlate", hypotheses=class_findings)
            try:
                merged = await run_correlator(
                    class_findings,
                    bundle.case_dir,
                    bundle.base_apk,
                    nonce,
                    recovered=bundle.facts.payloads,
                )
            except Exception as exc:
                errors.append(f"correlate: {exc}")
                merged = class_findings
            hypotheses = findings_for_verifier(bundle.case_dir, merged)
            server = build_case_server(bundle.case_dir, bundle.base_apk, nonce)
            findings_path = bundle.case_dir / "findings.json"
            findings_path.write_text(
                json.dumps([asdict(item) for item in hypotheses], indent=2),
                encoding="utf-8",
            )
            step("verifier", hypotheses=hypotheses)
            verifier_failed = False
            try:
                verification = await run_verifier(
                    hypotheses, server, nonce=nonce, cwd=bundle.case_dir
                )
            except Exception as exc:
                verifier_failed = True
                errors.append(f"verifier: {exc}")
            if verifier_failed:
                verdict = None
            else:
                grounded = {item.id: item for item in grounded_findings(bundle.case_dir, hypotheses)}
                quoted = {
                    item.id
                    for item in hypotheses
                    if any(evidence.quote.strip() for evidence in item.evidence)
                }
                verification = [
                    item
                    if item.status != "supported" or item.id not in quoted or item.id in grounded
                    else Verification(
                        id=item.id,
                        status="unsupported",
                        note="The quoted snippet is not in the cited artifact.",
                    )
                    for item in verification
                ]
                (bundle.case_dir / "verification.json").write_text(
                    json.dumps([asdict(item) for item in verification], indent=2),
                    encoding="utf-8",
                )
                supported = [item.id for item in verification if item.status == "supported"]
                supported_findings = [grounded[item] for item in supported if item in grounded]
                step("verdict", hypotheses=hypotheses, verification=verification)
                try:
                    verdict = await run_verdict(
                        bundle.facts,
                        supported_findings,
                        verification,
                        nonce=nonce,
                        cwd=bundle.case_dir,
                    )
                except Exception as exc:
                    errors.append(f"verdict: {exc}")
                else:
                    verdict, _note = enforce_verdict(verdict, supported, verification, hypotheses)

    report = Report(
        facts=bundle.facts,
        hypotheses=hypotheses,
        verification=verification,
        verdict=verdict,
        artifact_paths=list_artifacts(bundle.case_dir),
        errors=errors,
    )
    report_path = bundle.case_dir / "report.json"
    report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    report.artifact_paths = list_artifacts(bundle.case_dir)
    report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return report, report_path
