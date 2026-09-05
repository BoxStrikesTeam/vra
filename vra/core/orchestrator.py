"""Orchestrator for VRA - manages the full analysis pipeline."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from vra.analyzers.registry import AnalyzerRegistry, discover_analyzers
from vra.build.manager import BuildManager
from vra.core.config import VRAConfig
from vra.core.enums import AnalysisProfile, RunStatus, Severity
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ProjectInfo, RunMetadata
from vra.correlation.confidence import adjust_confidence
from vra.correlation.deduplicator import deduplicate_findings
from vra.correlation.merger import merge_findings
from vra.evidence.collector import collect_evidence
from vra.project.inspector import get_repository_info, inspect_project, vendored_hint
from vra.rules.engine import RuleEngine
from vra.security.classification import classify_finding_category
from vra.security.prioritizer import prioritize_findings

log = get_logger("orchestrator")

# Pattern-based taint sinks that have no dedicated rule and therefore are
# surfaced as standalone findings (rather than only enriching existing ones).
_STANDALONE_TAINT_SINKS = {"array_index", "alloc_overflow"}

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def _sev_rank(sev) -> int:
    if sev is None:
        return 0
    key = getattr(sev, "value", None) or str(sev).lower()
    return _SEVERITY_RANK.get(key, 0)


def _append_note(existing: str, note: str) -> str:
    prefix = f"{existing} | " if existing else ""
    return f"{prefix}{note}"


def _hit_sink_cwe(hit) -> str:
    if hit.sink_name == "array_index":
        return "CWE-787"
    if hit.sink_name == "alloc_overflow":
        return "CWE-120"
    return "CWE-0"


def _native_available() -> bool:
    try:
        from vra import _native as _c  # noqa: F401

        return True
    except ImportError:
        return False
PROFILE_ANALYZERS = {
    AnalysisProfile.QUICK: ["clang", "semgrep", "cppcheck"],
    AnalysisProfile.STANDARD: ["clang", "clang-tidy", "semgrep", "cppcheck", "codeql"],
    AnalysisProfile.DEEP: ["clang", "clang-tidy", "semgrep", "cppcheck", "codeql", "flawfinder"],
}


class Orchestrator:
    def __init__(
        self,
        config: VRAConfig,
        workspace: Path,
        progress_callback=None,
        total_stages: int = 7,
    ):
        self.config = config
        self.workspace = workspace
        self.progress_callback = progress_callback
        self.total_stages = total_stages
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._call_graph = None

    def _step(self, current: int, message: str) -> None:
        if self.progress_callback:
            try:
                self.progress_callback(current, self.total_stages, message)
            except Exception as e:  # pragma: no cover - defensive
                log.debug("Progress callback failed: %s", e)

    def analyze(self, source_path: Path) -> AnalysisContext:
        log.info("Starting analysis of %s", source_path)

        self._step(1, "Inspecting project")
        log.info("[1/7] Inspecting project...")
        project_info = inspect_project(source_path)

        self._step(2, "Detecting build system")
        log.info("[2/7] Detecting build system...")
        build_result = None
        if project_info.build_system.value != "unknown":
            log.info("Build system: %s", project_info.build_system.value)
            build_manager = BuildManager(project_info, self.workspace)
            build_result = build_manager.build()

        self._step(3, "Running analyzers")
        log.info("[3/7] Running analyzers...")
        tool_results = self._run_analyzers(project_info, build_result)

        all_findings: list[Finding] = []
        for tr in tool_results:
            all_findings.extend(tr.findings)

        self._step(4, "Running custom rules")
        log.info("[4/7] Running custom rules...")
        rule_engine = RuleEngine()
        rule_findings = rule_engine.run(project_info, self.workspace)
        all_findings.extend(rule_findings)

        self._step(5, "Correlating findings")
        log.info("[5/7] Correlating findings...")
        all_findings = deduplicate_findings(all_findings)
        all_findings = merge_findings(all_findings)

        for f in all_findings:
            f.category = classify_finding_category(f)
            adjust_confidence(f)
            collect_evidence(f)

        self._step(6, "Prioritizing findings")
        log.info("[6/7] Prioritizing findings...")
        all_findings = prioritize_findings(all_findings)

        for i, f in enumerate(all_findings):
            f.id = f"F-{i + 1:05d}"

        import time as _time

        self._step(7, "Enriching findings and persisting results")

        t0 = _time.monotonic()
        self._enrich_findings(all_findings, project_info)
        log.info("[TIMING] _enrich_findings took %.1fs for %d findings", _time.monotonic() - t0, len(all_findings))

        t0 = _time.monotonic()
        self._build_call_chains(all_findings, project_info)
        log.info("[TIMING] _build_call_chains took %.1fs for %d findings", _time.monotonic() - t0, len(all_findings))

        t0 = _time.monotonic()
        self._apply_taint(all_findings, project_info)
        log.info("[TIMING] _apply_taint took %.1fs for %d findings", _time.monotonic() - t0, len(all_findings))

        # _apply_taint may append standalone taint findings; (re)assign IDs so
        # every finding carries a stable, sequential identifier.
        for i, f in enumerate(all_findings):
            f.id = f"F-{i + 1:05d}"

        t0 = _time.monotonic()
        self._validate_rules(all_findings, project_info)
        log.info(
            "[TIMING] _validate_rules took %.1fs for %d findings",
            _time.monotonic() - t0,
            len(all_findings),
        )

        if self.config.ai.validate:
            t0 = _time.monotonic()
            self._validate_with_ai(all_findings, project_info)
            log.info(
                "[TIMING] _validate_with_ai took %.1fs for %d findings",
                _time.monotonic() - t0,
                len(all_findings),
            )

        ai_analysis = self._run_ai(all_findings, project_info)

        git_info = get_repository_info(source_path)
        run_metadata = RunMetadata(
            repo_url=git_info.get("remote_url", ""),
            commit_hash=git_info.get("commit_hash", ""),
            branch=git_info.get("branch", ""),
            timestamp=datetime.now(UTC).isoformat(),
            profile=self.config.profile,
            enabled_analyzers=[tr.analyzer_name for tr in tool_results if tr.status == RunStatus.COMPLETED],
        )

        context = AnalysisContext(
            project=project_info,
            build_result=build_result,
            run_metadata=run_metadata,
            workspace_dir=self.workspace,
            source_dir=source_path,
            all_findings=all_findings,
            tool_results=tool_results,
            ai_analysis=ai_analysis,
        )

        log.info("[7/7] Analysis complete. %d findings", len(all_findings))
        self._persist_run(context)
        return context

    def _run_ai(self, findings: list[Finding], project_info: ProjectInfo):
        if not self.config.ai.enabled:
            return None

        from vra.ai.optional import create_ai_provider, run_ai_analysis

        provider = create_ai_provider(self.config.ai)
        if getattr(provider, "provider_name", "") == "disabled":
            return None

        log.info("Running AI-assisted analysis (%s)...", provider.provider_name)
        analysis = run_ai_analysis(provider, findings, project_info)
        log.info("AI analysis complete: %d narratives", len(analysis.narratives))
        return analysis

    def _enrich_findings(self, findings: list[Finding], project_info: ProjectInfo) -> None:
        import time as _time

        if _native_available():
            from vra.native_backend import extract_snippet, find_function_at
        else:  # pragma: no cover - fallback
            from vra.analysis.function_locator import find_function_at  # type: ignore
            from vra.evidence.snippets import extract_snippet  # type: ignore

        total = len(findings)
        t_start = _time.monotonic()
        t_last = t_start
        for n, f in enumerate(findings, 1):
            if not f.source.function:
                f.source.function = find_function_at(f.source.file, f.source.line)
            f.source_snippet = extract_snippet(f.source.file, f.source.line)
            if not f.vendor_source and f.source.file:
                f.vendor_source = vendored_hint(Path(f.source.file), project_info.path) or ""
            if not f.fingerprint:
                from vra.correlation.fingerprint import compute_fingerprint

                f.fingerprint = compute_fingerprint(f)

            if n % 500 == 0 or n == total:
                now = _time.monotonic()
                log.info(
                    "[TIMING] enrich %d/%d done in %.1fs (chunk %.1fs, file=%s)",
                    n,
                    total,
                    now - t_start,
                    now - t_last,
                    f.source.file,
                )
                t_last = now
                if self.progress_callback:
                    self._step(7, f"Enriching findings... ({n}/{total})")

    def _build_call_chains(self, findings: list[Finding], project_info: ProjectInfo) -> None:
        import time as _time

        from vra.core.models import CallChainEntry

        t0 = _time.monotonic()
        try:
            if _native_available():
                from vra.native_backend import NativeCallGraphBuilder

                builder = NativeCallGraphBuilder(project_info.path)
            else:
                from vra.analysis.callgraph.builder import CallGraphBuilder

                builder = CallGraphBuilder(project_info.path)
            graph = builder.build()
        except Exception as e:  # pragma: no cover - fallback safety
            log.debug("Call graph build failed: %s", e)
            return
        self._call_graph = graph
        log.info("[TIMING] CallGraph build took %.1fs (%d functions)", _time.monotonic() - t0, len(graph.functions))

        t1 = _time.monotonic()
        log.info("[TIMING] entry_points: %s", graph.entry_points[:5])

        path_cache: dict[tuple, list[str] | None] = {}

        total = len(findings)
        reachable_count = 0
        path_found = 0
        for i, f in enumerate(findings, 1):
            sink_func = f.source.function
            if not sink_func or sink_func not in graph.functions and sink_func not in graph.function_files:
                continue

            if not graph.reachable_from_entry(sink_func):
                continue
            reachable_count += 1

            chain: list[str] | None = None
            for entry in graph.entry_points:
                key = (entry, sink_func)
                if key not in path_cache:
                    path_cache[key] = graph.build_path(entry, sink_func)
                chain = path_cache[key]
                if chain:
                    path_found += 1
                    break

            if chain:
                f.call_chain = [
                    CallChainEntry(function=name, file=graph.function_files.get(name, "")) for name in chain
                ]
                # Recompute reachability now that the chain is known (the earlier
                # enrichment pass could not determine it without entry-point data).
                from vra.analysis.reachability import estimate_reachability

                f.reachability = estimate_reachability(f)

            if i % 1000 == 0 or i == total:
                log.info(
                    "[TIMING] callchain %d/%d reachable=%d paths=%d cache=%d (%.1fs)",
                    i,
                    total,
                    reachable_count,
                    path_found,
                    len(path_cache),
                    _time.monotonic() - t1,
                )
                if self.progress_callback:
                    self._step(7, f"Building call chains... ({i}/{total})")

    def _apply_taint(self, findings: list[Finding], project_info: ProjectInfo) -> None:
        """Bind inter-procedural taint results onto findings.

        Runs the taint engine once for the whole project (cheap: a few seconds
        on large codebases thanks to the C backend), then matches recognised
        sink findings to their tainted-argument analysis. Populates
        ``controllability``, ``dataflow``, ``attack_surface`` and
        ``validation_info``.
        """
        import time as _time

        from vra.analysis.taint.engine import TaintEngine

        sink_by_line = {}
        try:
            if _native_available():
                from vra import _native as _c

                taint_data = _c.build_taint_data(str(project_info.path))
            else:  # pragma: no cover - fallback
                from vra.native_backend import build_taint_data

                taint_data = build_taint_data(str(project_info.path))
            engine = TaintEngine(
                taint_data,
                function_files=getattr(self._call_graph, "function_files", None),
            )
            t0 = _time.monotonic()
            results = engine.analyze()
            log.info(
                "[TIMING] taint analyze took %.1fs (%d tainted sinks)",
                _time.monotonic() - t0,
                sum(len(v) for v in results.values()),
            )
        except Exception as e:  # pragma: no cover - resilience
            log.warning("Taint analysis unavailable: %s", e)
            return

        # Index TaintedCall by (function, line) for lookup.
        for _fn, hits in results.items():
            for hit in hits:
                sink_by_line.setdefault((hit.func, hit.line), []).append(hit)

        from vra.analysis.taint.sanitizers import look_for_guard
        from vra.core.enums import ControllabilityLevel
        from vra.core.models import DataFlowStep, SourceLocation
        if _native_available():
            from vra.native_backend import extract_snippet
        else:  # pragma: no cover - fallback
            from vra.evidence.snippets import extract_snippet  # type: ignore

        for f in findings:
            if not f.source.function:
                continue
            hits = sink_by_line.get((f.source.function, f.source.line))
            if not hits or not hits[0].tainted_args:
                continue
            hit = hits[0]

            # Guard / sanitizer check: look at the real source around the sink.
            guard_present = False
            try:
                if f.source.file:
                    snippet = extract_snippet(f.source.file, hit.line)
                    guard_present = look_for_guard(snippet.splitlines())
            except Exception:  # pragma: no cover - best effort
                guard_present = False

            suffix = " (guarded)" if guard_present else ""
            f.controllability = (
                ControllabilityLevel.LOW if guard_present else ControllabilityLevel.HIGH
            )
            f.attack_surface = f.attack_surface or hit.source_hint or "unknown"
            f.validation_info = (
                f"tainted sink {hit.sink_name} at {f.source.function}:{f.source.line}; "
                f"tainted args: {', '.join(hit.tainted_args)}; source: {hit.source_hint or 'unknown'}"
                f"{suffix}"
            )
            # Use the engine's real provenance path (source -> ... -> sink).
            if hit.steps:
                filled = []
                for _s in hit.steps:
                    if _s.location and not _s.location.file:
                        _s.location.file = f.source.file
                    filled.append(_s)
                f.dataflow = filled
            else:
                f.dataflow = [
                    DataFlowStep(
                        variable=hit.tainted_args[0],
                        location=SourceLocation(
                            file=f.source.file,
                            line=f.source.line,
                            function=f.source.function,
                        ),
                        description=f"{hit.sink_name} called with attacker-influenced '{hit.tainted_args[0]}'",
                    )
                ]

        # Emit standalone findings for pattern-based taint sinks (array index,
        # allocation-size overflow) that do not correspond to any existing rule,
        # static-analysis or tool finding. They are the only sink kinds with no
        # built-in rule, so adding them here surfaces the checks the user asked
        # for without duplicating classic sinks (memcpy/system/...).
        from vra.core.enums import ControllabilityLevel, Severity
        from vra.core.models import Finding as VRAFinding

        for hits in sink_by_line.values():
            for hit in hits:
                if hit.sink_name not in _STANDALONE_TAINT_SINKS:
                    continue
                # These pattern-based sinks are surfaced as their own findings
                # regardless of any coincidental rule/tool finding on the same
                # line (they carry distinct CWE/category semantics).
                _fdesc = "Array index derived from attacker-influenced data"
                if hit.sink_name == "alloc_overflow":
                    _fdesc = "Allocation size derived from attacker-controlled factor"
                _loc = SourceLocation(
                    file=hit.file,
                    line=hit.line,
                    function=hit.func,
                )
                # Hit file may be empty when the engine lacked a function->file
                # map; recover it from the call graph (cheap, native-backed) or
                # from any provenance step that carries one.
                if not _loc.file and hit.func:
                    _loc.file = (
                        (getattr(self._call_graph, "function_files", None) or {}).get(
                            hit.func, ""
                        )
                        or _loc.file
                    )
                if not _loc.file:
                    for _s in hit.steps:
                        if _s.location and _s.location.file:
                            _loc.file = _s.location.file
                            break
                for _s in hit.steps:
                    if not _s.location.file:
                        _s.location.file = _loc.file
                    if not _s.location.function:
                        _s.location.function = hit.func
                findings.append(
                    VRAFinding(
                        id="",
                        title=_fdesc,
                        category="taint",
                        cwe=_hit_sink_cwe(hit),
                        severity=Severity.MEDIUM,
                        confidence=0.6 if not hit.guard_present else 0.3,
                        source=_loc,
                        tools=["taint:" + hit.sink_name],
                        dataflow=hit.steps,
                        controllability=(
                            ControllabilityLevel.LOW
                            if hit.guard_present
                            else ControllabilityLevel.HIGH
                        ),
                        attack_surface=hit.source_hint or "unknown",
                        validation_info=(
                            f"tainted sink {hit.sink_name} at {hit.func}:{hit.line}; "
                            f"tainted args: {', '.join(hit.tainted_args)}; "
                            f"source: {hit.source_hint or 'unknown'}"
                        ),
                    )
                )

    def _validate_rules(self, findings: list[Finding], project_info: ProjectInfo) -> None:
        """First FP-reduction stage: structural (rule-based) validation.

        Runs every finding through the validators that apply to it. Verdicts
        never drop findings; a ``LIKELY_FP`` verdict demotes the status, records
        the reason into ``validation_info`` + ``false_positive_indicators`` and
        re-runs confidence adjustment so the demotion is reflected in priority
        scores and reports.
        """
        import time as _time

        from vra.core.enums import FindingStatus, ValidationResult
        from vra.rules.validation import build_validation_engine

        engine = build_validation_engine(strict=self.config.validation.strict)
        content_cache: dict[str, str] = {}
        demoted = 0
        annotated = 0
        t0 = _time.monotonic()
        for f in findings:
            if not f.source.file:
                continue
            if f.source.file not in content_cache:
                try:
                    content_cache[f.source.file] = Path(f.source.file).read_text(errors="replace")
                except OSError:
                    continue
            content = content_cache[f.source.file]
            try:
                outcome = engine.validate(f, content, Path(f.source.file))
            except Exception:  # pragma: no cover - resilience
                continue

            if outcome.verdict is ValidationResult.LIKELY_FP:
                f.status = FindingStatus.LIKELY_FALSE_POSITIVE
                for ind in outcome.indicators:
                    if ind not in f.false_positive_indicators:
                        f.false_positive_indicators.append(ind)
                if outcome.reason:
                    f.validation_info = _append_note(
                        f.validation_info, f"structural validation: {outcome.reason}"
                    )
                demoted += 1
            elif outcome.verdict is ValidationResult.CONFIRMED and outcome.reason:
                f.validation_info = _append_note(
                    f.validation_info, f"structural validation: {outcome.reason}"
                )
                annotated += 1
            adjust_confidence(f)
        log.info(
            "Structural validation: %d/%d demoted (FP), %d structurally confirmed (%.1fs)",
            demoted,
            len(findings),
            annotated,
            _time.monotonic() - t0,
        )

    def _validate_with_ai(self, findings: list[Finding], project_info: ProjectInfo) -> None:
        """Second FP-reduction stage (optional): AI verification + devil's advocate.

        Pass-1 asks the model to classify each candidate as confirmed,
        suspicious or false_positive; Pass-2 (unless disabled) tries to disprove
        the survivors. Findings failing either pass are demoted to
        ``LIKELY_FALSE_POSITIVE`` with explanatory indicators. Fail-open: any
        model/parse error leaves all findings untouched.
        """
        import time as _time

        from vra.ai.devil_advocate import challenge_findings
        from vra.ai.optional import create_ai_provider
        from vra.ai.validator import verify_findings

        cfg = self.config.ai
        provider = create_ai_provider(cfg)
        if getattr(provider, "provider_name", "") == "disabled" or not cfg.model_command:
            log.warning("AI validation requested but no model is configured; skipping")
            return

        min_sev = {
            "all": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
        }.get(cfg.validate_scope, Severity.HIGH)
        candidates = [f for f in findings if _sev_rank(f.severity) >= _sev_rank(min_sev)]
        candidates.sort(key=lambda f: f.priority_score, reverse=True)
        candidates = candidates[: max(1, cfg.validate_limit or 200)]
        if not candidates:
            return

        t0 = _time.monotonic()
        verified = verify_findings(provider, candidates, project_info)
        if not verified:
            return

        survivors: list[Finding] = []
        for f in candidates:
            v = verified.get(f.id)
            if not v:
                survivors.append(f)
                continue
            if v.verdict == "false_positive":
                self._mark_ai_fp(f, "rejected by AI verifier", v.reason)
                continue
            if v.confidence_override is not None:
                capped = max(0.0, min(float(v.confidence_override), f.confidence))
                f.confidence = round(capped, 3)
            survivors.append(f)

        if cfg.devil_advocate and survivors:
            challenged = challenge_findings(provider, survivors, project_info)
            for f in survivors:
                c = challenged.get(f.id)
                if not c:
                    continue
                ind = f"devil's advocate: {c.reason}".strip()
                if c.verdict == "confirmed_fp":
                    self._mark_ai_fp(f, "disproven by devil's advocate", c.reason)
                elif c.verdict == "challenged" and ind not in f.false_positive_indicators:
                    f.false_positive_indicators.append(ind)
                    f.validation_info = _append_note(f.validation_info, ind)

        log.info(
            "AI validation: %d candidates verified in %.1fs",
            len(candidates),
            _time.monotonic() - t0,
        )

    def _mark_ai_fp(self, finding: Finding, stage: str, reason: str) -> None:
        from vra.core.enums import FindingStatus

        ind = f"{stage}: {reason}".strip()
        if ind not in finding.false_positive_indicators:
            finding.false_positive_indicators.append(ind)
        finding.status = FindingStatus.LIKELY_FALSE_POSITIVE
        finding.validation_info = _append_note(finding.validation_info, ind)
        adjust_confidence(finding)

    def _persist_run(self, context: AnalysisContext) -> None:
        import time as _time

        t0 = _time.monotonic()
        try:
            import json
            from datetime import datetime

            from vra.storage.database import (
                Database,
                EvidenceModel,
                FindingModel,
                ProjectModel,
                RunModel,
            )

            db = Database(self.workspace / "vra.db")
            with db.get_session() as session:
                # Replace any previous rows for the same project path so that a
                # re-analysis cannot collide on uniquely constrained finding ids
                # (every analysis re-issues stable ids starting at F-00001) nor
                # accumulate stale findings across runs.
                after = []
                for old in session.query(ProjectModel).filter_by(
                    path=str(context.project.path)
                ).all():
                    run_ids = [
                        r[0] for r in session.query(RunModel.id).filter(RunModel.project_id == old.id)
                    ]
                    if run_ids:
                        finding_pks = [
                            f[0]
                            for f in session.query(FindingModel.id)
                            .filter(FindingModel.run_id.in_(run_ids))
                        ]
                        if finding_pks:
                            session.query(EvidenceModel).filter(
                                EvidenceModel.finding_id.in_(finding_pks)
                            ).delete(synchronize_session=False)
                        session.query(FindingModel).filter(
                            FindingModel.run_id.in_(run_ids)
                        ).delete(synchronize_session=False)
                    session.query(RunModel).filter(
                        RunModel.project_id == old.id
                    ).delete(synchronize_session=False)
                    after.append(old)
                for old in after:
                    session.delete(old)
                session.flush()

                project = ProjectModel(
                    name=context.project.name,
                    path=str(context.project.path),
                    languages=",".join(context.project.languages),
                    build_system=context.project.build_system.value,
                    created_at=datetime.now(),
                )
                session.add(project)
                session.flush()
                log.debug("Persisted project id=%s path=%s", project.id, project.path)

                run = RunModel(
                    project_id=project.id,
                    commit_hash=context.run_metadata.commit_hash,
                    branch=context.run_metadata.branch,
                    profile=context.run_metadata.profile,
                    timestamp=datetime.now(),
                    status="completed",
                )
                session.add(run)
                session.flush()

                finding_models = []
                for f in context.all_findings:
                    finding_models.append(
                        FindingModel(
                            finding_id=f.id,
                            run_id=run.id,
                            title=f.title,
                            category=f.category,
                            cwe=f.cwe,
                            severity=f.severity.value,
                            confidence=f.confidence,
                            priority_score=f.priority_score,
                            file_path=f.source.file,
                            line=f.source.line,
                            function_name=f.source.function,
                            tools=",".join(f.tools),
                            reachability=f.reachability.value,
                            controllability=f.controllability.value,
                            status=f.status.value,
                            notes=f.notes,
                            fingerprint=f.fingerprint,
                            attack_surface=f.attack_surface,
                            source_snippet=f.source_snippet,
                            vendor_source=f.vendor_source,
                            call_chain=json.dumps(
                                [c.__dict__ for c in f.call_chain], default=str
                            )
                            if f.call_chain
                            else None,
                            dataflow=json.dumps(
                                [s.__dict__ for s in f.dataflow], default=str
                            )
                            if f.dataflow
                            else None,
                            created_at=datetime.now(),
                        )
                    )
                session.add_all(finding_models)
                session.commit()
                run_id = run.id
            log.info(
                "[TIMING] Persisted %d findings to %s in %.1fs (run id=%s)",
                len(context.all_findings),
                self.workspace / "vra.db",
                _time.monotonic() - t0,
                run_id,
            )
        except Exception as e:
            log.warning("Failed to persist findings to database: %s", e)

    def _run_analyzers(self, project_info: ProjectInfo, build_result) -> list:
        discover_analyzers()
        profile = (
            AnalysisProfile(self.config.profile)
            if self.config.profile in [e.value for e in AnalysisProfile]
            else AnalysisProfile.STANDARD
        )
        target_analyzers = PROFILE_ANALYZERS.get(profile, PROFILE_ANALYZERS[AnalysisProfile.STANDARD])

        # Sanitizer runs only when explicitly enabled via config.
        if profile == AnalysisProfile.DEEP and self.config.analyzers.sanitizer:
            target_analyzers = target_analyzers + ["sanitizer"]

        # Respect user's AnalyzerConfig toggles (false => skip that analyzer).
        cfg_map = {
            "clang": self.config.analyzers.clang_analyzer,
            "clang-tidy": self.config.analyzers.clang_tidy,
            "codeql": self.config.analyzers.codeql,
            "semgrep": self.config.analyzers.semgrep,
            "cppcheck": self.config.analyzers.cppcheck,
            "flawfinder": self.config.analyzers.flawfinder,
            "sanitizer": self.config.analyzers.sanitizer,
        }
        target_analyzers = [a for a in target_analyzers if cfg_map.get(a, True)]

        available = AnalyzerRegistry.get_available()
        to_run = [a for a in available if a.name in target_analyzers]

        if not to_run:
            log.warning("No analyzers available")
            return []

        context = AnalysisContext(
            project=project_info,
            build_result=build_result,
            workspace_dir=self.workspace,
            source_dir=project_info.path,
        )

        results = []
        done_count = 0
        with ThreadPoolExecutor(max_workers=min(len(to_run), 4)) as executor:
            future_to_analyzer = {executor.submit(self._run_single_analyzer, a, context): a for a in to_run}
            for future in as_completed(future_to_analyzer):
                analyzer = future_to_analyzer[future]
                done_count += 1
                try:
                    result = future.result()
                    results.append(result)
                    status = "FAILED" if result.status == RunStatus.FAILED else "COMPLETED"
                    log.info(
                        "  %s: %d findings (%.1fs)",
                        analyzer.name,
                        len(result.findings),
                        result.duration,
                    )
                    self._step(
                        3,
                        f"Analyzer {analyzer.name} {status} "
                        f"({done_count}/{len(to_run)} done, {len(result.findings)} findings",
                    )
                except Exception as e:
                    log.error("  %s failed: %s", analyzer.name, e)
                    from vra.core.models import ToolRunResult

                    failed_result = ToolRunResult(
                        analyzer_name=analyzer.name,
                        status=RunStatus.FAILED,
                        error_message=str(e),
                    )
                    results.append(failed_result)
                    self._step(
                        3,
                        f"Analyzer {analyzer.name} FAILED: {e} ({done_count}/{len(to_run)} done)",
                    )

        return results

    def _run_single_analyzer(self, analyzer, context):
        analyzer.prepare(context)
        return analyzer.run(context)
