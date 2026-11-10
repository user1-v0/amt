from pathlib import Path

from utils.snippets import code_window, evidence_snippet, locate_span


SOURCE = """class Listener {
    void onPosted() {
        socket.emit("0xNO", payload);
        return;
    }
}
"""


def test_locate_span_finds_an_exact_quote():
    start, end = locate_span(SOURCE, 'socket.emit("0xNO", payload);')
    assert SOURCE[start:end] == 'socket.emit("0xNO", payload);'


def test_code_window_keeps_surrounding_lines_and_the_quote_offset():
    start, end = locate_span(SOURCE, 'socket.emit("0xNO", payload);')
    snippet, highlight_start, highlight_end = code_window(SOURCE, start, end)
    assert "void onPosted()" in snippet
    assert snippet[highlight_start:highlight_end] == 'socket.emit("0xNO", payload);'


def test_evidence_snippet_reads_the_case_file(tmp_path: Path):
    dex = tmp_path / "dex"
    dex.mkdir()
    (dex / "Listener.java").write_text(SOURCE, encoding="utf-8")
    shown = evidence_snippet(tmp_path, "dex/Listener.java", 'emit("0xNO"')
    assert shown["snippet"][shown["highlight_start"] : shown["highlight_end"]] == 'emit("0xNO"'
    assert "void onPosted()" in shown["snippet"]


def test_missing_file_highlights_the_quote_itself():
    shown = evidence_snippet(None, "dex/Missing.java", "sendSms")
    assert shown == {"snippet": "sendSms", "highlight_start": 0, "highlight_end": 7}
