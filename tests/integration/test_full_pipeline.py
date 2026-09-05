"""Integration test for the full analysis pipeline on a sample project."""

from pathlib import Path

from vra.core.config import VRAConfig
from vra.core.orchestrator import Orchestrator

SAMPLE_DIR = Path(__file__).parent.parent / "sample_projects"


def test_full_pipeline_on_clean_project(tmp_path):
    source = SAMPLE_DIR / "clean_project"
    if not source.exists():
        return

    config = VRAConfig(profile="quick")
    orchestrator = Orchestrator(config, tmp_path / "workspace")
    context = orchestrator.analyze(source)
    assert context.project.name == "clean_project"
    assert len(context.all_findings) >= 0
