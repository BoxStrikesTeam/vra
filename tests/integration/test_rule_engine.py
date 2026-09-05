"""Integration test for the rule engine on sample vulnerable projects."""

from pathlib import Path

from vra.core.models import ProjectInfo
from vra.rules.engine import RuleEngine

SAMPLE_DIR = Path(__file__).parent.parent / "sample_projects"


def test_rule_engine_finds_bugs_in_sample_projects(tmp_path):
    engine = RuleEngine()
    engine.load_rules()
    patterns_found = {}

    for sample in ["use_after_free", "double_free", "buffer_overflow", "integer_overflow"]:
        project_path = SAMPLE_DIR / sample
        if not project_path.exists():
            continue
        project = ProjectInfo(path=project_path, name=sample)
        findings = engine.run(project, tmp_path)
        categories = {f.category for f in findings}
        patterns_found[sample] = categories

    assert "use_after_free" in patterns_found
    assert "memory" in patterns_found.get("use_after_free", set())
    assert "memory" in patterns_found.get("buffer_overflow", set())
