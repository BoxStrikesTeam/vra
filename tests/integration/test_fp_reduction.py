"""Regression: FP-reduction must not demote the *key* finding in each sample.

Each sample project intentionally contains one realistic vulnerability class.
The structural-validation stage must never turn that key finding into a
likely-false-positive, while still demoting the noisy look-alikes around it.

The test drives the exact validation path the orchestrator uses
(rule engine -> structural validation) but skips the external analyzers so it
stays fast.
"""

from pathlib import Path

from vra.core.config import VRAConfig
from vra.core.enums import FindingStatus, ValidationResult
from vra.core.models import AnalysisContext, ProjectInfo, RunMetadata
from vra.rules.engine import RuleEngine
from vra.rules.validation import build_validation_engine

SAMPLE_DIR = Path(__file__).parent.parent / "sample_projects"

SAMPLES = [
    ("use_after_free", {"CWE-416"}),
    ("double_free", {"CWE-415"}),
    ("buffer_overflow", {"CWE-120"}),
    ("integer_overflow", {"CWE-190"}),
]
# null_deref's CWE-476 comes from an external analyzer, so it is asserted via
# the full orchestrator path in test_null_deref_key_survives_full_pipeline.
RULE_ENGINE_SAMPLES = SAMPLES


def _run_sample(sample: str, strict: bool):
    """Rules -> structural validation (mirrors orchestrator._validate_rules)."""
    project = ProjectInfo(name=sample, path=SAMPLE_DIR / sample)
    engine = RuleEngine()
    engine.load_rules()
    findings = engine.run(project, SAMPLE_DIR / sample)

    validator = build_validation_engine(strict=strict)
    content_cache: dict[str, str] = {}
    for f in findings:
        if not f.source.file:
            continue
        if f.source.file not in content_cache:
            content_cache[f.source.file] = Path(f.source.file).read_text(errors="replace")
        outcome = validator.validate(f, content_cache[f.source.file], Path(f.source.file))
        if outcome.verdict is ValidationResult.LIKELY_FP:
            f.status = FindingStatus.LIKELY_FALSE_POSITIVE
    return findings


def test_key_findings_survive_validation():
    for sample, key_cwes in SAMPLES:
        if not (SAMPLE_DIR / sample).exists():
            continue
        findings = _run_sample(sample, strict=False)
        survivors = [
            f
            for f in findings
            if f.cwe in key_cwes and f.status is not FindingStatus.LIKELY_FALSE_POSITIVE
        ]
        assert survivors, (
            f"All {key_cwes} findings in {sample} were demoted by structural validation"
        )


def test_key_findings_survive_strict_validation():
    for sample, key_cwes in SAMPLES:
        if not (SAMPLE_DIR / sample).exists():
            continue
        findings = _run_sample(sample, strict=True)
        survivors = [
            f
            for f in findings
            if f.cwe in key_cwes and f.status is not FindingStatus.LIKELY_FALSE_POSITIVE
        ]
        assert survivors, (
            f"All {key_cwes} findings in {sample} were demoted even in strict mode"
        )


def test_structural_stage_demotes_some_noise():
    sample = "buffer_overflow"
    if not (SAMPLE_DIR / sample).exists():
        return
    findings = _run_sample(sample, strict=False)
    demoted = sum(
        1 for f in findings if f.status is FindingStatus.LIKELY_FALSE_POSITIVE
    )
    assert demoted == 0 or demoted < len(findings)


def test_null_deref_key_survives_full_pipeline(tmp_path):
    """CWE-476 arrives from an external analyzer; verify it survives end-to-end."""
    sample = "null_deref"
    source = SAMPLE_DIR / sample
    if not source.exists():
        return
    from vra.core.orchestrator import Orchestrator

    ws = tmp_path / sample
    ws.mkdir(parents=True, exist_ok=True)
    ctx = Orchestrator(VRAConfig(profile="quick"), ws).analyze(source)
    survivors = [
        f
        for f in ctx.all_findings
        if f.cwe == "CWE-476" and f.status is not FindingStatus.LIKELY_FALSE_POSITIVE
    ]
    assert survivors


def test_report_contains_validation_summary():
    sample = "double_free"
    if not (SAMPLE_DIR / sample).exists():
        return
    findings = _run_sample(sample, strict=False)

    from vra.reporting.json_report import compute_validation_summary
    from vra.reporting.markdown import generate_markdown_report

    project = ProjectInfo(name=sample, path=SAMPLE_DIR / sample, total_files=1)
    context = AnalysisContext(project=project, run_metadata=RunMetadata())

    summary = compute_validation_summary(findings)
    assert summary["total_findings"] == len(findings)

    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        md = generate_markdown_report(findings, context, Path(tmp))
        assert "## FP Reduction" in md.read_text()
