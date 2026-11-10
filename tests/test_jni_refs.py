from pathlib import Path

from tools import native_decompiler
from tools.native_decompiler import (
    JavaNativeRefs,
    collect_java_native_refs,
    decompiled_jni_names,
    decode_jni,
    jni_candidates,
    jni_referenced,
    keep_for_decompile,
    referenced_jni_report,
)


def test_decode_jni_method_and_underscore_in_class_name():
    assert decode_jni("Java_com_example_App_start") == ("com.example.App", "start")
    assert decode_jni("sym.Java_com_example_My_1Class_open__I") == ("com.example.My_Class", "open")
    assert decode_jni("JNI_OnLoad") is None


def test_unused_native_declaration_is_not_a_reference(tmp_path: Path):
    dex = tmp_path / "dex"
    dex.mkdir()
    (dex / "com.example.App.java").write_text(
        "package com.example;\npublic class App {\n  public native void start();\n}\n",
        encoding="utf-8",
    )
    refs = collect_java_native_refs([dex])
    assert jni_referenced("Java_com_example_App_start", refs) is False
    assert keep_for_decompile("Java_com_example_App_start", refs) is False
    assert keep_for_decompile("JNI_OnLoad", refs) is False
    assert keep_for_decompile("decodePacket", refs) is False


def test_called_native_method_and_literal_symbol_are_kept(tmp_path: Path):
    dex = tmp_path / "dex"
    dex.mkdir()
    (dex / "com.example.App.java").write_text(
        "package com.example;\npublic class App {\n"
        "  public native void start();\n"
        "  void run() { this.start(); }\n}\n",
        encoding="utf-8",
    )
    (dex / "com.example.Other.java").write_text(
        'void register() { System.load("Java_com_example_Hidden_decode"); }\n',
        encoding="utf-8",
    )
    refs = collect_java_native_refs([dex])
    assert ("com.example.App", "start") in refs.methods
    assert jni_referenced("Java_com_example_App_start", refs) is True
    assert jni_referenced("Java_com_example_Hidden_decode", refs) is True
    assert keep_for_decompile("sym.Java_com_example_App_start", refs) is True


def test_call_from_another_class_counts(tmp_path: Path):
    dex = tmp_path / "dex"
    dex.mkdir()
    (dex / "com.example.App.java").write_text(
        "package com.example;\npublic class App { public native int open(); }\n",
        encoding="utf-8",
    )
    (dex / "com.example.Main.java").write_text(
        "package com.example;\npublic class Main { void go() { App.open(); } }\n",
        encoding="utf-8",
    )
    refs = collect_java_native_refs([dex])
    assert refs.methods == frozenset({("com.example.App", "open")})


def test_decompiled_jni_names_keep_methods_with_pseudocode():
    report = """skipped 1 JNI methods with no reference in the decompiled Java

## sym.JNI_OnLoad
jint JNI_OnLoad(void) { return 0; }

## sym.Java_com_example_App_start @ 0x1000

## Java_com_example_App_open
int open(void) { return 1; }

## sym.decodePacket
int decode(void) { return 2; }
"""
    assert decompiled_jni_names(report) == ["JNI_OnLoad", "Java_com_example_App_open"]


def test_empty_refs_skip_jni_methods():
    refs = JavaNativeRefs(frozenset(), frozenset())
    assert keep_for_decompile("Java_com_example_App_start", refs) is False
    assert keep_for_decompile("native_helper", refs) is False
    assert keep_for_decompile("Java_com_example_App_start", None) is False


def test_jni_candidates_leave_out_the_rest_of_the_library():
    exports = [{"name": "decodePacket", "vaddr": 1}, {"name": "JNI_OnLoad", "vaddr": 2}]
    functions = [{"name": "sym.Java_com_example_App_start", "offset": 7}]
    assert [item["name"] for item in jni_candidates(exports, functions)] == [
        "sym.Java_com_example_App_start"
    ]


def test_referenced_jni_report_drops_unused_functions():
    refs = JavaNativeRefs(frozenset({("com.example.App", "start")}), frozenset())
    report = """## JNI_OnLoad
jint JNI_OnLoad(void) { return 0; }

## Java_com_example_App_start
int start(void) { return 1; }

## decodePacket
int decode(void) { return 2; }
"""
    shown = referenced_jni_report(report, refs)
    assert "return 1" in shown
    assert "JNI_OnLoad" not in shown
    assert "decodePacket" not in shown


def test_several_libraries_are_analyzed_in_a_process_pool(monkeypatch):
    seen: dict[str, object] = {}

    class Pool:
        def __init__(self, max_workers, mp_context):
            seen["workers"] = max_workers
            seen["method"] = mp_context.get_start_method()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def map(self, fn, jobs):
            seen["count"] = len(list(jobs))
            return [("sym.a", "a", True, None), ("sym.b", "b", False, None)]

    monkeypatch.setattr(native_decompiler, "ProcessPoolExecutor", Pool)
    refs = JavaNativeRefs(frozenset(), frozenset())
    results = native_decompiler._analyze_libraries([Path("liba.so"), Path("libb.so")], refs)

    assert seen["workers"] == native_decompiler._worker_count(2)
    assert seen["method"] == "spawn"
    assert seen["count"] == 2
    assert [item[0] for item in results] == ["sym.a", "sym.b"]
    assert native_decompiler._uses_process_pool(1) is False
