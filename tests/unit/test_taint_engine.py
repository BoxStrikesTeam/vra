"""Tests for the taint engine and vendored-source tagging."""

from __future__ import annotations

from pathlib import Path

import pytest

from vra import _native as c
from vra.analysis.taint.engine import TaintEngine
from vra.analysis.taint.sinks import find_sink
from vra.project.inspector import is_vendored_path, vendored_hint

pytestmark = pytest.mark.skipif(
    not hasattr(c, "build_taint_data"), reason="native taint backend not available"
)

INTERPROC = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_sink(char *user_data) {
    char buf[64];
    strcpy(buf, user_data);
}

void process(char *input) {
    vulnerable_sink(input);
}

int main(int argc, char **argv) {
    process(argv[1]);
    return 0;
}
"""


def _proj(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    return root


def test_inter_procedural_taint(tmp_path: Path):
    src = _proj(tmp_path) / "ip.c"
    src.write_text(INTERPROC)
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    # sink strcpy detected in vulnerable_sink with tainted user_data
    hits = results.get("vulnerable_sink")
    assert hits, f"expected sink in vulnerable_sink, got {list(results)}"
    assert any(h.sink_name == "strcpy" and h.tainted_args for h in hits)
    # The provenance path should be non-trivial: provenance + terminal sink step.
    assert all(len(h.steps) >= 1 for h in hits if h.tainted_args)


def test_dataflow_steps_include_provenance(tmp_path: Path):
    src = _proj(tmp_path) / "trace.c"
    src.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "#include <stdlib.h>\n"
        "void go(char *user_input) {\n"
        "    char line[64];\n"
        "    snprintf(line, sizeof(line), \"%s\", user_input);\n"
        "    system(line);\n"
        "}\n"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    hits = results.get("go")
    assert hits
    hit = next(h for h in hits if h.sink_name == "system")
    # Expect an entry/taint provenance step for 'line' plus the sink step.
    steps = hit.steps
    assert any(s.variable == "line" and s.location.line == 6 for s in steps)
    assert any("system" in s.description and s.location.line == 7 for s in steps)


def test_source_identifier_param(tmp_path: Path):
    src = _proj(tmp_path) / "src.c"
    src.write_text(
        "int handler(char *argv, int argc) {\n"
        "    return 0;\n"
        "}\n"
        "void f(char *user_cmd) {\n"
        "    char b[8];\n"
        "    system(user_cmd);\n"
        "}\n"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    hits = results.get("f")
    assert hits, f"expected system sink, got {list(results)}"
    assert any(h.sink_name == "system" and "user_cmd" in h.tainted_args for h in hits)


def test_sanitized_sink_not_flagged(tmp_path: Path):
    src = _proj(tmp_path) / "clean.c"
    src.write_text(
        "void safe(char *data, size_t n) { char b[10]; if (n < sizeof(b)) { "
        "strncpy(b, data, n); } }"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    # strncpy is a bounded alternative; our engine only flags raw strcpy/sprintf
    hits = results.get("safe", [])
    assert not any(h.sink_name == "strcpy" for h in hits)


def test_constant_arg_not_source(tmp_path: Path):
    src = _proj(tmp_path) / "const.c"
    src.write_text(
        "int main(void) {\n"
        '    system("ls");\n'
        "    return 0;\n"
        "}\n"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    hits = results.get("main", [])
    # A literal "ls" string is not attacker controlled => not a tainted sink.
    assert not any(h.sink_name == "system" and h.tainted_args for h in hits)


def test_find_sink_table():
    spec = find_sink("memcpy", ["d", "s", "n"])
    assert spec is not None
    assert spec.arg_is_risky(2)
    assert not spec.arg_is_risky(0)
    assert find_sink("system", ["x"]).all_args is True
    assert find_sink("puts", ["x"]) is None


def test_vendored_path_detection():
    assert is_vendored_path(["src", "3rdparty", "sqlite3.c"])
    assert is_vendored_path(["vendor", "lib", "a.c"])
    assert is_vendored_path(["external", "foo.c"])
    assert not is_vendored_path(["src", "core", "own.c"])


def test_vendored_hint(tmp_path: Path):
    root = tmp_path / "proj"
    vendor_file = root / "src" / "3rdparty" / "sqlite3.c"
    vendor_file.parent.mkdir(parents=True)
    vendor_file.write_text("int x;")
    own = root / "src" / "main.c"
    own.write_text("int main(){}")
    assert vendored_hint(vendor_file, root) is not None
    assert "3rdparty" in vendored_hint(vendor_file, root)
    assert vendored_hint(own, root) is None


def test_tainted_array_index_detected(tmp_path: Path):
    src = _proj(tmp_path) / "idx.c"
    src.write_text(
        "#include <stdio.h>\n"
        "int g(const char *buf) { return buf[0]; }\n"
        "void go(char *user_input, int idx) {\n"
        "    char data[64];\n"
        "    int k = parse(user_input) + idx;\n"
        "    char c = data[k];\n"
        "    (void)c;\n"
        "}\n"
        "int main(int argc, char **argv) { return 0; }\n"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    hits = results.get("go", [])
    assert any(
        h.sink_name == "array_index" and "k" in h.tainted_args for h in hits
    ), f"expected array_index on tainted index, got {[h.sink_name for h in hits]}"


def test_tainted_alloc_overflow_detected(tmp_path: Path):
    src = _proj(tmp_path) / "alloc.c"
    src.write_text(
        "#include <stdlib.h>\n"
        "void go(char *user_input) {\n"
        "    int n = atoi(user_input);\n"
        "    void *p = malloc(n * 8);\n"
        "    (void)p;\n"
        "}\n"
    )
    data = c.build_taint_data(str(tmp_path))
    engine = TaintEngine(data)
    results = engine.analyze()
    hits = results.get("go", [])
    assert any(
        h.sink_name == "alloc_overflow" and "n" in h.tainted_args for h in hits
    ), f"expected alloc_overflow, got {[(h.sink_name, h.tainted_args) for h in hits]}"
    hit = next(h for h in hits if h.sink_name == "alloc_overflow")
    assert len(hit.steps) >= 2
    assert any("n" in s.variable and s.location.line == 3 for s in hit.steps)
