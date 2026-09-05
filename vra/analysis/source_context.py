"""Source context extraction for VRA."""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("analysis.source_context")


def extract_source_context(finding: Finding, project_path: Path) -> str:
    file_path = project_path / finding.source.file
    if not file_path.exists():
        return ""

    try:
        lines = file_path.read_text(errors="ignore").split("\n")
    except OSError:
        return ""

    start = max(0, finding.source.line - 20)
    end = min(len(lines), finding.source.line + 20)

    context_lines = []
    for i in range(start, end):
        marker = ">>>" if i == finding.source.line - 1 else "   "
        context_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")

    func_sig = _extract_function_signature(lines, finding.source.line - 1)
    if func_sig:
        context_lines.insert(0, f"     | Function: {func_sig}")

    return "\n".join(context_lines)


def _extract_function_signature(lines: list[str], target_line: int) -> str:
    for i in range(target_line, max(-1, target_line - 30), -1):
        line = lines[i].strip()
        if re.match(
            r"^(static\s+|extern\s+|inline\s+)*(void|int|char|unsigned|size_t|ssize_t|bool|float|double|const\s+\w+|struct\s+\w+|enum\s+\w+|\w+\s*\*)",
            line,
        ):
            if "(" in line:
                return line
    return ""
