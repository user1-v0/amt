"""Extract and decompile native libraries with r2pipe and r2ghidra."""

from __future__ import annotations

import multiprocessing
import os
import re
import zipfile
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path

from schemas import NativeLib
from utils.limits import MAX_FUNCTIONS_PER_LIB, MAX_NATIVE_BYTES

_LIB_MEMBER = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
_SYMBOL = re.compile(r"^(?:0x[0-9a-fA-F]+|sym\.[A-Za-z0-9_$.]+|[A-Za-z_][A-Za-z0-9_$.]*)$")
_PREFERRED_ABIS = ("arm64-v8a", "armeabi-v7a")
_NATIVE_JAVA = re.compile(r"\bnative\s+(?:[\w.\[\]$<>]+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NATIVE_SMALI = re.compile(r"^\.method\b[^\n]*\bnative\b[^\n]*?\s([A-Za-z_$][\w$]*)\(", re.M)
_JNI_SYMBOL = re.compile(r"\bJava_[A-Za-z0-9_]+")
_SOURCE_SUFFIXES = {".java", ".smali", ".kt"}


@dataclass(frozen=True)
class JavaNativeRefs:
    """Native methods the decompiled Java actually calls, plus literal JNI symbol strings."""

    methods: frozenset[tuple[str, str]]
    symbols: frozenset[str]


@dataclass
class SoMember:
    apk_name: str
    apk_path: str
    member_name: str
    abi: str
    soname: str
    size: int


def list_so_members(apk: Path) -> list[SoMember]:
    found: list[SoMember] = []
    try:
        archive = zipfile.ZipFile(apk)
    except zipfile.BadZipFile:
        return found
    with archive:
        for info in archive.infolist():
            match = _LIB_MEMBER.match(info.filename.replace("\\", "/"))
            if match is None:
                continue
            found.append(
                SoMember(
                    apk_name=apk.name,
                    apk_path=str(apk),
                    member_name=info.filename,
                    abi=match.group(1),
                    soname=match.group(2),
                    size=info.file_size,
                )
            )
    return found


def select_native(members: list[SoMember], prefer: tuple[str, ...] = ()) -> list[SoMember]:
    """Keep one ABI per library. Prefer arm64-v8a, then armeabi-v7a.

    When a preferred ABI is present, libraries that only exist for another
    ABI are left out. Otherwise the first copy of each library is kept.
    Names in prefer are kept ahead of the size cap so the framework payload
    is not dropped when an APK ships many libraries.
    """
    present = {member.abi for member in members}
    preferred = next((abi for abi in _PREFERRED_ABIS if abi in present), None)
    grouped: dict[str, list[SoMember]] = {}
    for member in members:
        grouped.setdefault(member.soname, []).append(member)
    chosen: list[SoMember] = []
    for group in grouped.values():
        if preferred:
            matches = [member for member in group if member.abi == preferred]
            if not matches:
                continue
            chosen.append(matches[0])
        else:
            chosen.append(group[0])
    prefer_rank = [name.lower() for name in prefer]

    def sort_key(member: SoMember) -> tuple:
        try:
            rank = prefer_rank.index(member.soname.lower())
        except ValueError:
            rank = len(prefer_rank)
        return (rank, member.soname, member.abi)

    chosen.sort(key=sort_key)
    return chosen


def extract_so(member: SoMember, dest: Path) -> str | None:
    """Extract one library. Returns an error string when the file is skipped."""
    if member.size > MAX_NATIVE_BYTES:
        return f"{member.soname} is larger than the native size cap"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(member.apk_path) as archive:
        info = archive.getinfo(member.member_name)
        if info.file_size > MAX_NATIVE_BYTES:
            return f"{member.soname} is larger than the native size cap"
        with archive.open(info) as source, dest.open("wb") as output:
            remaining = MAX_NATIVE_BYTES
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                output.write(chunk)
                remaining -= len(chunk)
    return None


def validate_symbol(name: str) -> str:
    cleaned = name.strip()
    if not _SYMBOL.fullmatch(cleaned):
        raise ValueError(f"invalid native symbol: {name!r}")
    return cleaned


def _bare(name: str) -> str:
    return name.removeprefix("sym.")


def is_jni_method(name: str) -> bool:
    """A Java_* export. JNI_OnLoad stays out of this set because the VM calls it."""
    bare = _bare(name)
    return bare.startswith("Java_")


def decode_jni(name: str) -> tuple[str, str] | None:
    """Map Java_com_example_App_start to (com.example.App, start)."""
    bare = _bare(name)
    if not bare.startswith("Java_"):
        return None
    body = bare[len("Java_") :].split("__", 1)[0]
    decoded = _decode_jni_body(body)
    if "." not in decoded:
        return "", decoded
    owner, method = decoded.rsplit(".", 1)
    if not owner or not method:
        return None
    return owner, method


def _decode_jni_body(body: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(body):
        if body.startswith("_1", index):
            out.append("_")
            index += 2
            continue
        if body.startswith("_0", index) and index + 6 <= len(body):
            hexpart = body[index + 2 : index + 6]
            if all(char in "0123456789abcdefABCDEF" for char in hexpart):
                out.append(chr(int(hexpart, 16)))
                index += 6
                continue
        if body[index] == "_":
            out.append(".")
            index += 1
            continue
        out.append(body[index])
        index += 1
    return "".join(out)


def collect_java_native_refs(roots: list[Path]) -> JavaNativeRefs:
    """Native methods called from decompiled Java or smali, and literal Java_ symbols."""
    files: list[tuple[str, str]] = []
    symbols: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            files.append((_owner_from_source(path, text), text))
            symbols.update(_JNI_SYMBOL.findall(text))
    methods: set[tuple[str, str]] = set()
    for owner, text in files:
        for method in _declared_native_methods(text):
            if _native_method_is_called(owner, method, text, files):
                methods.add((owner, method))
    return JavaNativeRefs(frozenset(methods), frozenset(symbols))


def jni_referenced(name: str, refs: JavaNativeRefs) -> bool:
    bare = _bare(name)
    if bare in refs.symbols:
        return True
    decoded = decode_jni(name)
    if decoded is None:
        return False
    return decoded in refs.methods


def keep_for_decompile(name: str, refs: JavaNativeRefs | None) -> bool:
    """Decompile a JNI method only when a manifest class calls it."""
    if refs is None or not is_jni_method(name):
        return False
    return jni_referenced(name, refs)


def _owner_from_source(path: Path, text: str) -> str:
    if "." in path.stem:
        return path.stem
    package = ""
    package_match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
    if package_match:
        package = package_match.group(1)
    class_match = re.search(r"\bclass\s+([A-Za-z_][\w$]*)", text)
    if class_match:
        name = class_match.group(1)
        return f"{package}.{name}" if package else name
    return path.stem


def _declared_native_methods(text: str) -> set[str]:
    found = {match.group(1) for match in _NATIVE_JAVA.finditer(text)}
    found.update(match.group(1) for match in _NATIVE_SMALI.finditer(text))
    return found


def _call_count(text: str, method: str) -> int:
    return len(re.findall(rf"(?<![\w$]){re.escape(method)}\s*\(", text))


def _native_method_is_called(
    owner: str, method: str, declaring: str, files: list[tuple[str, str]]
) -> bool:
    if _call_count(declaring, method) > _declaration_count(declaring, method):
        return True
    simple = owner.rsplit(".", 1)[-1]
    qualified = re.compile(
        rf"(?<![\w$]){re.escape(simple)}\s*\.\s*{re.escape(method)}\s*\("
    )
    smali_owner = owner.replace(".", "/")
    smali = re.compile(rf"{re.escape(smali_owner)};->{re.escape(method)}\(")
    for _other_owner, text in files:
        if qualified.search(text) or smali.search(text):
            return True
    return False


def _declaration_count(text: str, method: str) -> int:
    pattern = re.compile(
        rf"\bnative\s+(?:[\w.\[\]$<>]+\s+)+{re.escape(method)}\s*\("
    )
    smali = re.compile(
        rf"^\.method\b[^\n]*\bnative\b[^\n]*?\s{re.escape(method)}\(",
        re.M,
    )
    return len(pattern.findall(text)) + len(smali.findall(text))


def _priority(name: str) -> int:
    bare = _bare(name)
    if bare == "JNI_OnLoad" or bare.startswith("Java_") or bare.startswith("JNI_"):
        return 0
    return 1


def decompiled_jni_names(report: str) -> list[str]:
    """JNI methods whose decompiler report includes a pseudocode body."""
    names: list[str] = []
    for chunk in re.split(r"(?m)^## ", report):
        chunk = chunk.strip()
        if not chunk:
            continue
        header, _, body = chunk.partition("\n")
        symbol = header.split(" @ ", 1)[0].strip()
        bare = symbol.removeprefix("sym.")
        if not (bare.startswith("Java_") or bare.startswith("JNI_")):
            continue
        if not body.strip():
            continue
        names.append(bare)
    return names


def jni_methods_for_library(case_dir: Path | None, soname: str) -> list[str]:
    if case_dir is None or not soname or "/" in soname or soname.startswith("."):
        return []
    notes = case_dir / "native" / "notes" / f"{soname}.txt"
    if not notes.is_file():
        return []
    return decompiled_jni_names(notes.read_text(encoding="utf-8", errors="replace"))


def jni_candidates(exports: list[dict], functions: list[dict]) -> list[dict]:
    """Every Java_* symbol. Other functions in the library are left out."""
    ranked: list[dict] = []
    seen: set[str] = set()

    def add(name: str, vaddr: int | None) -> None:
        key = _bare(name)
        if not key or key in seen or not is_jni_method(name):
            return
        seen.add(key)
        ranked.append({"name": name, "vaddr": vaddr})

    for function in functions:
        name = str(function.get("name") or "")
        offset = function.get("offset")
        add(name, offset if isinstance(offset, int) else None)
    for export in exports:
        name = str(export.get("name") or "")
        vaddr = export.get("vaddr")
        add(name, vaddr if isinstance(vaddr, int) else None)
    ranked.sort(key=lambda item: item["name"])
    return ranked


def referenced_jni_report(report: str, refs: JavaNativeRefs) -> str:
    """Keep pseudocode for JNI methods the manifest classes call."""
    kept: list[str] = []
    for chunk in re.split(r"(?m)^## ", report):
        chunk = chunk.strip()
        if not chunk:
            continue
        header, _, body = chunk.partition("\n")
        symbol = header.split(" @ ", 1)[0].strip()
        if not keep_for_decompile(symbol, refs) or not body.strip():
            continue
        kept.append(f"## {header}\n{body.strip()}")
    if not kept:
        return "No JNI method used by a class named in the manifest was decompiled from this library.\n"
    return "\n\n".join(kept) + "\n"


def rank_symbols(exports: list[dict], functions: list[dict]) -> list[dict]:
    ranked: list[dict] = []
    seen: set[str] = set()

    def add(name: str, vaddr: int | None, priority: int) -> None:
        key = _bare(name)
        if not key or key in seen:
            return
        seen.add(key)
        ranked.append({"name": name, "vaddr": vaddr, "priority": priority})

    for function in functions:
        name = str(function.get("name") or "")
        offset = function.get("offset")
        vaddr = offset if isinstance(offset, int) else None
        if _priority(name) == 0:
            add(name, vaddr, 0)
    for export in exports:
        name = str(export.get("name") or "")
        vaddr = export.get("vaddr")
        if not isinstance(vaddr, int):
            vaddr = None
        add(name, vaddr, _priority(name))
    ranked.sort(key=lambda item: (item["priority"], item["name"]))
    return ranked[:MAX_FUNCTIONS_PER_LIB]


def _pdg_available(probe: str) -> bool:
    lowered = probe.lower()
    return "pdg" in lowered and "not found" not in lowered and "cannot find" not in lowered


def _decompile_symbol(r2, symbol: dict, pdg_ok: bool) -> str:
    if not pdg_ok:
        return ""
    vaddr = symbol.get("vaddr")
    if isinstance(vaddr, int):
        target = hex(vaddr)
    else:
        name = str(symbol.get("name") or "")
        try:
            target = validate_symbol(name if name.startswith("sym.") or name.startswith("0x") else f"sym.{name}")
        except ValueError:
            return ""
    text = r2.cmd(f"pdg @ {target}") or ""
    lowered = text.lower()
    if not text.strip() or "not found" in lowered or "cannot find" in lowered:
        return ""
    return text.strip()


def analyze_so(
    so_path: Path, java_refs: JavaNativeRefs | None = None
) -> tuple[list[str], str, bool, str | None]:
    """Return function names, a text report, whether pseudocode was produced, and an error."""
    try:
        import r2pipe
    except ImportError:
        return [], "", False, "r2pipe is not installed"
    try:
        r2 = r2pipe.open(
            str(so_path),
            flags=["-2", "-e", "anal.timeout=30", "-e", "scr.color=0"],
        )
    except Exception as exc:
        return [], "", False, f"radare2 failed to open {so_path.name}: {exc}"
    try:
        r2.cmd("aa")
        exports = r2.cmdj("iEj") or []
        functions = r2.cmdj("aflj") or []
        if not isinstance(exports, list):
            exports = []
        if not isinstance(functions, list):
            functions = []
        symbols = jni_candidates(exports, functions)
        pdg_ok = _pdg_available(r2.cmd("pdg?") or "")
        sections: list[str] = []
        produced = False
        kept = [symbol for symbol in symbols if keep_for_decompile(str(symbol["name"]), java_refs)]
        skipped = len(symbols) - len(kept)
        kept = kept[:MAX_FUNCTIONS_PER_LIB]
        if not pdg_ok:
            sections.append("r2ghidra pdg is unavailable. Function names are listed without pseudocode.")
        if skipped:
            sections.append(
                f"skipped {skipped} JNI methods with no call from a class named in the manifest"
            )
        if not kept:
            sections.append("no JNI method used by a class named in the manifest")
        for symbol in kept:
            header = symbol["name"]
            if isinstance(symbol.get("vaddr"), int):
                header = f"{header} @ {hex(symbol['vaddr'])}"
            body = _decompile_symbol(r2, symbol, pdg_ok)
            if body:
                produced = True
                sections.append(f"## {header}\n{body}")
            else:
                sections.append(f"## {header}\n")
        names = [str(symbol["name"]) for symbol in kept]
        report = "\n\n".join(sections).strip()
        notes: list[str] = []
        if not pdg_ok:
            notes.append("r2ghidra pdg is unavailable")
        if skipped:
            notes.append(
                f"skipped {skipped} JNI methods with no call from a class named in the manifest"
            )
        return names, report, produced, "; ".join(notes) or None
    except Exception as exc:
        return [], "", False, f"radare2 analysis failed: {exc}"
    finally:
        try:
            r2.quit()
        except Exception:
            pass


_REAL_ANALYZE_SO = analyze_so


def _uses_process_pool(library_count: int) -> bool:
    """Real radare2 runs in child processes. A replaced analyzer stays in this process."""
    return library_count > 1 and analyze_so is _REAL_ANALYZE_SO


def _worker_count(library_count: int) -> int:
    return max(1, min(library_count, os.cpu_count() or 1))


def _analyze_native_job(payload: tuple[str, JavaNativeRefs]) -> tuple[list[str], str, bool, str | None]:
    so_path, java_refs = payload
    try:
        return analyze_so(Path(so_path), java_refs)
    except Exception as exc:
        return [], "", False, f"native analysis failed: {exc}"


def _analyze_libraries(
    paths: list[Path], java_refs: JavaNativeRefs
) -> list[tuple[list[str], str, bool, str | None]]:
    if not _uses_process_pool(len(paths)):
        return [analyze_so(path, java_refs) for path in paths]
    jobs = [(str(path), java_refs) for path in paths]
    try:
        context = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=_worker_count(len(jobs)), mp_context=context) as pool:
            return list(pool.map(_analyze_native_job, jobs))
    except (OSError, BrokenProcessPool):
        return [analyze_so(path, java_refs) for path in paths]


def decompile_symbol(so_path: Path, function: str) -> tuple[str, str | None]:
    """Decompile one function already chosen by the caller."""
    function = validate_symbol(function)
    try:
        import r2pipe
    except ImportError:
        return "", "r2pipe is not installed"
    if not so_path.is_file():
        return "", f"library not found: {so_path.name}"
    try:
        r2 = r2pipe.open(
            str(so_path),
            flags=["-2", "-e", "anal.timeout=30", "-e", "scr.color=0"],
        )
    except Exception as exc:
        return "", f"radare2 failed to open {so_path.name}: {exc}"
    try:
        r2.cmd("aa")
        if not _pdg_available(r2.cmd("pdg?") or ""):
            return "", "r2ghidra pdg is unavailable"
        target = function if function.startswith("sym.") or function.startswith("0x") else f"sym.{function}"
        text = r2.cmd(f"pdg @ {target}") or ""
        if not text.strip():
            return "", f"no pseudocode for {function}"
        return text.strip(), None
    except Exception as exc:
        return "", f"radare2 analysis failed: {exc}"
    finally:
        try:
            r2.quit()
        except Exception:
            pass


def collect_native(
    apks: list[Path],
    native_dir: Path,
    prefer: tuple[str, ...] = (),
    java_roots: list[Path] | None = None,
) -> tuple[list[NativeLib], list[str]]:
    members: list[SoMember] = []
    for apk in apks:
        members.extend(list_so_members(apk))
    if not members:
        return [], []
    notes: list[str] = []
    java_refs = collect_java_native_refs(java_roots or [])
    selected = select_native(members, prefer)
    dropped = len({member.soname for member in members}) - len(selected)
    if dropped > 0:
        notes.append(f"native selection kept {len(selected)} libraries and skipped {dropped}")
    libraries: list[NativeLib | None] = []
    pending: list[tuple[int, SoMember, Path]] = []
    for member in selected:
        rel = Path("native") / member.abi / member.soname
        dest = native_dir / member.abi / member.soname
        error = extract_so(member, dest)
        if error:
            libraries.append(
                NativeLib(
                    apk=member.apk_name,
                    abi=member.abi,
                    name=member.soname,
                    path=rel.as_posix(),
                    size=member.size,
                    status="skipped",
                    note=error,
                )
            )
            continue
        libraries.append(None)
        pending.append((len(libraries) - 1, member, dest))
    analyzed = _analyze_libraries([dest for _index, _member, dest in pending], java_refs)
    notes_dir = native_dir / "notes"
    if pending:
        notes_dir.mkdir(parents=True, exist_ok=True)
    for (index, member, _dest), (names, report, produced, note) in zip(pending, analyzed, strict=True):
        (notes_dir / f"{member.soname}.txt").write_text(report, encoding="utf-8")
        failed = bool(note) and not names and not produced and "skipped" not in note
        libraries[index] = NativeLib(
            apk=member.apk_name,
            abi=member.abi,
            name=member.soname,
            path=f"native/{member.abi}/{member.soname}",
            size=member.size,
            status="error" if failed else "ok",
            functions=names,
            pseudocode=produced,
            note=note,
            jni_methods=decompiled_jni_names(report),
        )
        if note and "skipped" in note:
            notes.append(f"{member.soname}: {note}")
    finished = [item for item in libraries if item is not None]
    selected_names = {member.soname for member in selected}
    recorded = {lib.name for lib in finished}
    for member in members:
        if member.soname in selected_names or member.soname in recorded:
            continue
        recorded.add(member.soname)
        finished.append(
            NativeLib(
                apk=member.apk_name,
                abi=member.abi,
                name=member.soname,
                path=f"native/{member.abi}/{member.soname}",
                size=member.size,
                status="skipped",
                note="not selected; the preferred ABI copy is decompiled",
            )
        )
    return finished, notes
