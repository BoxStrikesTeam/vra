# VRA Architecture

VRA (Vulnerability Research Automation) is a C/C++ vulnerability-research
*assistance* tool. It aggregates evidence from multiple static-analysis tools,
applies deterministic custom rules, correlates the results, and produces
prioritized reports for human review. It does **not** confirm vulnerabilities
and does **not** generate exploits or payloads.

## Pipeline

```
source/
  │
  ▼
Project Inspector ──► language / build-system / risk-surface detection
  │
  ▼
Build Manager ──► CMake / Meson / Make : produces compile_commands.json
  │
  ▼
Analyzer Scheduler ──► parallel: clang-tidy, clang, semgrep, cppcheck, codeql, flawfinder
  │
  ▼
Custom Rule Engine ──► deterministic source-level rules (memory/logic/input)
  │
  ▼
Correlation ──► fingerprint → deduplicate → merge → confidence → classify
  │
  ▼
Enrichment ──► reachability, controllability, source snippet, call chain
  │
  ▼
Prioritization ──► severity × confidence → priority score
  │
  ▼
Optional AI ──► narrative summary (template engine or pluggable LLM)
  │
  ▼
Persistence (SQLite)  ──►  Reports (HTML / Markdown / JSON)
```

## Key Modules

| Module | Responsibility |
|--------|----------------|
| `vra/core/` | Models, config, orchestration, caching, enums |
| `vra/project/` | Project and repository inspection |
| `vra/build/` | Build-system drivers (CMake, Meson, Make) |
| `vra/analyzers/` | Tool adapters with `available→prepare→run→parse→normalize` |
| `vra/rules/` | Custom security rules and rule engine |
| `vra/correlation/` | Fingerprinting, deduplication, merging, confidence |
| `vra/security/` | CWE mapping, classification, prioritization |
| `vra/analysis/` | Reachability, call-graph construction |
| `vra/evidence/` | Evidence collection, source snippets |
| `vra/ai/` | Optional AI narrative layer |
| `vra/reporting/` | HTML / Markdown / JSON report generators |
| `vra/storage/` | SQLite persistence |
| `vra/cli/` | Typer-based command-line interface |

## Adding a New Rule

Rules are deterministic source-level pattern matchers. Each rule:

1. Subclasses `SecurityRule` from `vra.rules.base`.
2. Declares `name`, `category`, `cwe`, and a `severity` policy.
3. Implements `detect(project, ctx)` returning raw finding data.
4. Is registered automatically by placing it under `vra/rules/<category>/`
   and importing it in the corresponding `__init__.py`.

## Adding a New Analyzer

1. Subclass `Analyzer` from `vra.analyzers.base`, implementing
   `available()`, `prepare()`, `run()`, `parse()`, and `normalize()`.
2. Drop the adapter in `vra/analyzers/` and import it in
   `vra/analyzers/__init__.py` so it is registered.
3. Add its name to `PROFILE_ANALYZERS` in `vra/core/orchestrator.py`
   if it should run for a given profile.

## Security Guarantees

- Findings are **candidates**, never confirmed vulnerabilities.
- Language is cautious (`Potential`, `Likely`, `High-confidence`, `manual validation required`).
- Missing analyzers degrade gracefully; source rules still run.
- Fingerprints are deterministic (sha256 of normalized finding data).
- Short-circuit and depth-limited scanning avoids path traversal and hangs.

## Development

```bash
make install-dev
make test     # pytest
make lint     # ruff check + format --check
```
