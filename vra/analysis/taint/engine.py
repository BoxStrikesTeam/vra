"""Inter-procedural taint engine for VRA.

Consumes the rich function-level data extracted by the C extension
(``vra._native.build_taint_data``): per function parameter names, call sites
with their argument lists, and intra-procedural assignments.

The engine performs a practical, fixed-point taint propagation:

1. **Intra-procedural**: for each function, compute which local variables and
   parameters are tainted from source calls / assignments.
2. **Inter-procedural fixed-point**: a call ``f(a)`` propagates the taint of
   ``a`` onto ``f``'s corresponding parameter; ``y = g()`` marks ``y`` tainted
   if ``g`` returns tainted data. We iterate to a fixed point over the call
   graph.
3. **Sink matching**: for every recognised sink call we record which risky
   argument positions are tainted, producing a taint path (source -> sink).

The output is per-(function, sink call site) taint results that the orchestrator
can match to findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vra.analysis.taint.sinks import (
    ALLOC_OVERFLOW_NAME,
    ALLOC_OVERFLOW_SINK,
    INDEX_SINK,
    INDICES_INDEX_NAME,
    find_sink,
)
from vra.analysis.taint.sources import NETWORKISH_HINT, SOURCE_IDENTIFIER_RE, source_hint_for_call
from vra.core.models import DataFlowStep

_MAX_ITERATIONS = 8


@dataclass
class TaintStep:
    variable: str
    line: int
    description: str


@dataclass
class TaintedCall:
    """A sink call site where at least one risky arg is tainted."""

    func: str
    file: str
    sink_name: str
    line: int
    risky_args: list[int]
    tainted_args: list[str]          # arg substrings that carry taint
    steps: list[DataFlowStep] = field(default_factory=list)
    source_hint: str = ""
    guard_present: bool = False


@dataclass
class ReturnTaint:
    """Whether a function can return tainted data."""
    possible: bool = False
    sources: list[str] = field(default_factory=list)


@dataclass
class _FnData:
    params: list[str]
    calls: list[dict]     # {callee, args, line}
    assigns: list[dict]   # {var, value, line}
    signature_hint: str = ""


class TaintEngine:
    """Fixed-point taint analysis over function-level data."""

    def __init__(self, taint_data: dict, function_files: dict[str, str] | None = None):
        """
        Args:
            taint_data: dict from ``vra._native.build_taint_data`` with keys
                "params", "calls", "assigns" (each mapping function -> list).
            function_files: optional {func: rel_path} mapping for locations.
        """
        self.files: dict[str, str] = function_files or {}
        self._load(taint_data)

        # per-function set of possibly tainted local variable names
        self._local_taint: dict[str, set[str]] = {}
        # per-function set of tainted *parameters*
        self._param_taint: dict[str, set[str]] = {}
        # per-function possible-return-taint
        self._ret: dict[str, ReturnTaint] = {}
        # resolved sinks per function
        self._sinks: dict[str, list[TaintedCall]] = {}
        # taint provenance: func -> {var: [(line, source_hint): first-seen]}
        self._taint_trace: dict[str, dict[str, list[tuple[int, str]]]] = {}

    # ------------------------------------------------------------------ setup
    def _load(self, data: dict) -> None:
        self.functions: dict[str, _FnData] = {}
        raw_params = data.get("params", {})
        raw_calls = data.get("calls", {})
        raw_assigns = data.get("assigns", {})
        all_names = set(raw_params) | set(raw_calls) | set(raw_assigns)
        for name in all_names:
            params = [p for p in raw_params.get(name, []) if p and p not in ("void", "void )", ")")]
            self.functions[name] = _FnData(
                params=params,
                calls=self._clean_call_list(raw_calls.get(name, [])),
                assigns=self._clean_assign_list(raw_assigns.get(name, [])),
            )

    @staticmethod
    def _clean_call_list(calls: list) -> list[dict]:
        out = []
        for item in calls:
            if not isinstance(item, (tuple, list)) or len(item) < 3:
                continue
            callee, args, line = item[0], item[1], item[2]
            if isinstance(args, (list, tuple)):
                args = [str(a).strip() for a in args]
            else:
                args = []
            out.append({"callee": str(callee), "args": [a for a in args if a], "line": int(line)})
        return out

    @staticmethod
    def _clean_assign_list(assigns: list) -> list[dict]:
        out = []
        for item in assigns:
            if not isinstance(item, (tuple, list)) or len(item) < 3:
                continue
            var, value, line = item[0], item[1], item[2]
            out.append({"var": str(var), "value": str(value), "line": int(line)})
        return out

    # ------------------------------------------------------------- public API
    def analyze(self) -> dict[str, list[TaintedCall]]:
        """Run the fixed-point taint analysis. Returns {func: [TaintedCall,...]}."""
        # Iterate to a fixed point over inter-procedural parameter taint.
        for _ in range(_MAX_ITERATIONS):
            changed = self._iterate()
            if not changed:
                break

        # Second pass: now that parameter taint is fixed, detect sinks.
        self._detect_sinks()
        return self._sinks

    def _iterate(self) -> bool:
        changed = False
        for name, fn in self.functions.items():
            previous = self._param_taint.get(name, set())
            new_taint = self._compute_param_taint(name)
            if new_taint != previous:
                self._param_taint[name] = new_taint
                changed = True
        # Propagate return taint after parameter taint is updated.
        for name in self.functions:
            self._ret[name] = self._compute_return_taint(name)
        return changed

    # ---------------------------------------------------------------- helpers
    def _is_source_identifier(self, expr: str) -> bool:
        return bool(SOURCE_IDENTIFIER_RE.search(expr))

    def _source_for_identifier(self, name: str) -> str:
        # delegate to sources helper reusing surface logic
        low = name.lower()
        if "env" in low:
            return "environment"
        if any(x in low for x in ("cmd", "command", "shell", "exec")):
            return "cli"
        if low in ("argv", "argc", "optarg", "user_arg", "param", "arg"):
            return "cli"
        if any(x in low for x in ("input", "data", "buf", "buffer", "payload", "msg", "src")):
            return "network"
        return "network"

    def _expr_tainted(self, expr: str, local: set[str], params: set[str], fn: _FnData) -> set[str]:
        """Whether an expression references a tainted variable. Returns source hints."""
        result: set[str] = set()
        # Direct identifier or field/deref of a tainted variable.
        ident = re_search_ident(expr)
        for tok in ident:
            if tok in local or tok in params:
                result.add(self._source_for_identifier(tok))
        # Source calls inside the expression (e.g. getenv(...) embedded).
        for call_name, hint in _source_call_items():
            if call_name in expr:
                result.add(hint)
        # Clear taint when expression is a pure constant/number.
        if expr.strip().lstrip("-").isdigit():
            result.discard("network")
        return result

    def _raw_var_taint(self, var: str, kind: str) -> bool:
        """Whether a variable is intrinsically tainted by name or signature."""
        if kind == "param":
            if self._is_source_identifier(var):
                return True
            # Network-ish signature on the owning function is handled upstream.
        return False

    def _compute_param_taint(self, name: str) -> set[str]:
        fn = self.functions.get(name)
        if not fn:
            return set()
        tainted: set[str] = set()
        trace: dict[str, list[tuple[int, str]]] = {}

        def mark(var: str, line: int, hint: str) -> None:
            tainted.add(var)
            trace.setdefault(var, []).append((line, hint))

        # Parameters that are sources by name (tainted from entry point).
        net_fn = bool(NETWORKISH_HINT.search(name))
        for p in fn.params:
            if self._is_source_identifier(p) or net_fn:
                mark(p, 0, "network" if net_fn else self._source_for_identifier(p))

        # Intra-procedural: assignments from source calls / tainted expressions,
        # plus call-output propagation (a call that writes a tainted value into
        # its first buffer argument marks that buffer tainted). We iterate to a
        # small fixed point so chains like x->y->z are discovered.
        for _round in range(4):
            before = len(tainted)
            for a in fn.assigns:
                hints = self._expr_tainted(a["value"], tainted, tainted, fn)
                if hints:
                    mark(a["var"], a["line"], next(iter(hints)))
            for c in fn.calls:
                # e.g. snprintf(buf, n, fmt, tainted) -> buf tainted at this line.
                if c["args"] and c["args"][0]:
                    out_var = c["args"][0]
                    if self._any_arg_tainted(c["args"][1:], tainted, tainted):
                        if _is_buffer_filler(c["callee"]):
                            mark(out_var, c["line"], "network")
            if len(tainted) == before:
                break

        # De-duplicate per variable, keeping lowest (first) line per hint.
        clean: dict[str, list[tuple[int, str]]] = {}
        for var, records in trace.items():
            seen: dict[str, int] = {}
            for line, hint in records:
                if hint not in seen or line < seen[hint]:
                    seen[hint] = line
            clean[var] = sorted((ln, h) for h, ln in seen.items())
        self._taint_trace[name] = clean
        return tainted

    @staticmethod
    def _any_arg_tainted(args: list, local: set[str], param_t: set[str]) -> bool:
        for a in args:
            for tok in re_search_ident(a):
                if tok in local or tok in param_t:
                    return True
            for call_name, _ in _source_call_items():
                if call_name in a:
                    return True
        return False

    def _compute_return_taint(self, name: str) -> ReturnTaint:
        fn = self.functions.get(name)
        if not fn:
            return ReturnTaint()
        r = ReturnTaint()
        local: set[str] = set(self._param_taint.get(name, set()))
        for a in fn.assigns:
            if a["var"] in local or self._expr_tainted(a["value"], local, local, fn):
                local.add(a["var"])
        for c in fn.calls:
            hint = source_hint_for_call(c["callee"])
            if hint:
                r.possible = True
                r.sources.append(hint)
        # If any assignment feeds a tainted value into a "return" style variable,
        # we conservatively allow return taint if the function taints locals or has
        # any tainted params.
        if local or (self._param_taint.get(name)):
            r.possible = True
            if not r.sources:
                r.sources.append(self._source_for_identifier(name) if name else "unknown")
        return r

    # ------------------------------------------------------------- sink pass
    def _detect_sinks(self) -> None:
        self._sinks = {}
        for fname, fn in self.functions.items():
            # Recompute full intra+inter taint for this function (includes call
            # output propagation such as snprintf writing a tainted value).
            local = self._compute_param_taint(fname)
            param_t = local
            hits: list[TaintedCall] = []
            for call in fn.calls:
                callee = call["callee"]
                args = call["args"]
                spec = find_sink(callee, args)
                if not spec:
                    continue
                risky = spec.risky_args if not spec.all_args else list(range(len(args)))
                tainted_flags: list[str] = []
                for idx in risky:
                    if idx < 0 or idx >= len(args):
                        if spec.all_args:
                            for a in args:
                                if self._arg_t(a, local, param_t, fn) and a not in tainted_flags:
                                    tainted_flags.append(a)
                        continue
                    if self._arg_t(args[idx], local, param_t, fn):
                        if args[idx] not in tainted_flags:
                            tainted_flags.append(args[idx])
                if not tainted_flags:
                    # Fall back to calling argue all args if sink marks all risky.
                    if spec.all_args and any(self._arg_t(a, local, param_t, fn) for a in args):
                        tainted_flags = list(args)
                if not tainted_flags:
                    continue
                source_hint = self._best_source(tainted_flags, local)

                # Build a real provenance path: for each tainted argument, list
                # the earliest line where it became tainted (0 == function entry).
                from vra.core.models import DataFlowStep, SourceLocation

                trace = self._taint_trace.get(fname, {})
                steps: list[DataFlowStep] = []
                _file_for = self.files.get(fname, "")
                for arg in tainted_flags:
                    # Only chase simple identifiers we have provenance for.
                    idents = [t for t in re_search_ident(arg) if t in trace]
                    for var in idents:
                        for line, hint in trace.get(var, []):
                            loc = SourceLocation(file=_file_for, line=line, function=fname)
                            if line == 0:
                                desc = f"'{var}' enters {fname} as attacker-influenced data ({hint})"
                            else:
                                desc = f"'{var}' becomes tainted at this line ({hint})"
                            steps.append(DataFlowStep(variable=var, location=loc, description=desc))
                # Append the sink itself as the terminal step.
                sink_loc = SourceLocation(
                    file=_file_for, line=call["line"], function=fname
                )
                steps.append(
                    DataFlowStep(
                        variable=", ".join(tainted_flags) or callee,
                        location=sink_loc,
                        description=f"{callee} reached with tainted data",
                    )
                )

                hits.append(TaintedCall(
                    func=fname,
                    file=_file_for,
                    sink_name=callee,
                    line=call["line"],
                    risky_args=risky,
                    tainted_args=tainted_flags,
                    steps=steps,
                    source_hint=source_hint or "unknown",
                    guard_present=False,
                ))
            # Array-index / out-of-bounds reads and writes on tainted indices.
            self._detect_indices(fname, fn, local, param_t, hits)
            # Allocation-size overflow from tainted multiplication factors.
            # Allocation calls appear either as standalone calls or embedded as
            # the RHS of an assignment (e.g. `p = malloc(n * 8);`), which the
            # native extractor records as an assignment line, so scan both.
            alloc_calls = list(fn.calls)
            for a in fn.assigns:
                m = _ALLOC_CALL_RE.search(a["value"])
                if m:
                    alloc_calls.append({
                        "callee": m.group(1),
                        "args": _split_args(m.group(2)),
                        "line": a["line"],
                    })
            for call in alloc_calls:
                if call["callee"] in _ALLOC_FUNCS:
                    self._record_alloc_overflow(fname, fn, call, local, param_t, hits)
            if hits:
                self._sinks[fname] = hits

    @staticmethod
    def _arg_t(expr: str, local: set[str], param_t: set[str], fn: _FnData) -> bool:
        ident = re_search_ident(expr)
        for tok in ident:
            if tok in local or tok in param_t:
                return True
        for call_name, _ in _source_call_items():
            if call_name in expr:
                return True
        return False

    # -------------------------------------------------- alloc/array patterns
    def _record_alloc_overflow(
        self,
        fname: str,
        fn: _FnData,
        call: dict,
        local: set[str],
        param_t: set[str],
        hits: list[TaintedCall],
    ) -> None:
        """Flag allocation sizes built from tainted multiplication factors."""
        args = call["args"]
        risky_args = [0, 1] if call["callee"] == "calloc" else [0]
        tainted_factors: list[str] = []
        for idx in risky_args:
            if idx >= len(args):
                continue
            arg = args[idx]
            factors = [t for t in re_search_ident(arg) if t in local or t in param_t]
            if factors and _HAS_MULT.search(arg):
                tainted_factors.extend(factors)
        if not tainted_factors:
            return
        self._append_pattern_hit(
            fname, fn, call["line"], ALLOC_OVERFLOW_NAME, ALLOC_OVERFLOW_SINK,
            tainted_factors, local, hits,
            desc="allocation size derived from tainted multiplication factor",
        )

    def _detect_indices(
        self,
        fname: str,
        fn: _FnData,
        local: set[str],
        param_t: set[str],
        hits: list[TaintedCall],
    ) -> None:
        """Flag tainted values used as array subscripts (out-of-bounds)."""
        seen: set[tuple[int, str]] = set()
        expressions: list[tuple[str, int]] = []
        for a in fn.assigns:
            expressions.append((a["value"], a["line"]))
        for c in fn.calls:
            for arg in c["args"]:
                expressions.append((arg, c["line"]))

        for expr, line in expressions:
            for arr, idx in _SUBSCRIPT_RE.findall(expr):
                idents = re_search_ident(idx)
                if not idents:
                    continue
                tainted_idx = [t for t in idents if t in local or t in param_t]
                if tainted_idx and (line, arr) not in seen:
                    seen.add((line, arr))
                    self._append_pattern_hit(
                        fname, fn, line, INDICES_INDEX_NAME, INDEX_SINK,
                        tainted_idx, local, hits,
                        desc=f"tainted value used as index into '{arr}'",
                    )

    def _append_pattern_hit(
        self,
        fname: str,
        fn: _FnData,
        line: int,
        sink_name: str,
        spec,
        tainted_args: list[str],
        local: set[str],
        hits: list[TaintedCall],
        desc: str,
    ) -> None:
        """Build a TaintedCall for a pattern-based sink and append it."""
        from vra.core.models import SourceLocation

        trace = self._taint_trace.get(fname, {})
        _file_for = self.files.get(fname, "")
        steps: list[DataFlowStep] = []
        for var in tainted_args:
            for tl, hint in trace.get(var, []):
                sl = SourceLocation(file=_file_for, line=tl, function=fname)
                if tl == 0:
                    d = f"'{var}' enters {fname} as attacker-influenced data ({hint})"
                else:
                    d = f"'{var}' becomes tainted at this line ({hint})"
                steps.append(DataFlowStep(variable=var, location=sl, description=d))
        sink_loc = SourceLocation(file=_file_for, line=line, function=fname)
        steps.append(DataFlowStep(
            variable=", ".join(tainted_args),
            location=sink_loc,
            description=desc,
        ))
        source_hint = self._best_source(tainted_args, local)
        hits.append(TaintedCall(
            func=fname,
            file=_file_for,
            sink_name=sink_name,
            line=line,
            risky_args=[0],
            tainted_args=list(tainted_args),
            steps=steps,
            source_hint=source_hint or "unknown",
            guard_present=False,
        ))

    def _best_source(self, flags: list[str], local: set[str]) -> str:
        choices = ["network", "cli", "filesystem", "environment", "configuration", "stdin"]
        for c in choices:
            if any(c in (f or "").lower() for f in flags) or c == "network" and flags:
                return c
        return "unknown"

    # ------------------------------------------------- returning taint data
    def results_for_func(self, func: str) -> list[TaintedCall]:
        return self._sinks.get(func, [])


# ---------------------------------------------------------------------------
# Small helpers to avoid importing regex machinery repeatedly.
# ---------------------------------------------------------------------------
import re as _re  # noqa: E402

_IDENT_RE = _re.compile(r"[A-Za-z_]\w*")
_SOURCE_CALL_ITEMS = None

_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "alloca"}
_HAS_MULT = _re.compile(r"\w+\s*\*\s*\w+")
_SUBSCRIPT_RE = _re.compile(r"(\w+)\s*\[\s*([^\]]+?)\s*\]")
_ALLOC_CALL_RE = _re.compile(r"\b(malloc|calloc|realloc|alloca)\s*\(([^;()]*)\)", _re.I)


def _split_args(args: str) -> list[str]:
    """Split a comma-separated argument string on top-level commas."""
    out = []
    depth = 0
    cur = ""
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def re_search_ident(expr: str) -> list[str]:
    if not expr:
        return []
    return list(dict.fromkeys(_IDENT_RE.findall(expr)))


def _source_call_items():
    global _SOURCE_CALL_ITEMS
    if _SOURCE_CALL_ITEMS is None:
        from vra.analysis.taint.sources import SOURCE_CALLS

        _SOURCE_CALL_ITEMS = list(SOURCE_CALLS.items())
    return _SOURCE_CALL_ITEMS


_BUFFER_FILLERS = {
    "snprintf", "vsnprintf", "sprintf", "vsprintf", "strcpy", "strncpy",
    "strlcpy", "strcat", "strncat", "memcpy", "memmove", "memset", "sscanf",
}
_IDENT_ONLY_RE = _re.compile(r"^[A-Za-z_]\w*$")


def _is_buffer_filler(name: str) -> bool:
    return name in _BUFFER_FILLERS or name.startswith("sqlite3_snprintf")
