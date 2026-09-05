# VRA - Vulnerability Research Automation

VRA is a **vulnerability research assistance and evidence aggregation tool** for C/C++ open-source projects. It does **not** replace manual security review.

VRA automates the tedious parts of vulnerability research:
- Building and inspecting projects
- Running multiple static-analysis tools
- Normalizing and correlating findings across tools
- Extracting source context and call chains
- Applying deterministic custom security rules
- Prioritizing results for human review
- Generating professional reports

VRA does **not** perform automatic exploitation, payload generation, or vulnerability confirmation. The human researcher makes the final security decisions.

```
Scanner → Evidence → Normalization → Correlation → Source Context
  → Deterministic Security Reasoning → Prioritization → Human Review → Report
```

## Why does it exist?

C/C++ security research typically involves running dozens of tools and manually aggregating their output. VRA removes the busywork — reading hundreds of scanner results, deduplicating findings, collecting source context, mapping CWE, searching for risky primitives, generating reports, and converting between tool output formats — so the researcher can focus on what matters: understanding, verifying, and assessing the findings.

## Architecture

```
                     ┌───────────────────────┐
                     │       CLI / TUI       │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │      ORCHESTRATOR     │
                     └───────────┬───────────┘
          ┌──────────────────────┼───────────────────────┐
          ▼                      ▼                       ▼
 Project Inspector        Build Manager           Configuration
          │                      │
          └──────────┬───────────┘
                     ▼
              Compilation DB
                     ▼
              Analysis Scheduler
                     │
      ┌──────────────┼────────────────┐
      ▼              ▼                ▼
  CodeQL         Clang-tidy        Semgrep
      │              │                │
      └──────────────┼────────────────┘
                     ▼
            Finding Normalizer
                     ▼
            Finding Correlation
                     │
      ┌──────────────┼────────────────┐
      ▼              ▼                ▼
   AST/CFG       Call Graph      Data Flow
      │              │                │
      └──────────────┼────────────────┘
                     ▼
             Security Reasoning
                     ▼
              Risk Prioritizer
                     ▼
             Evidence Builder
                     ▼
              Report Generator
```

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/your-org/vra
cd vra
pip install -e .
```

## Dependencies

### Core (installed automatically)
- Python 3.11+
- typer, rich, pyyaml, pydantic, jinja2, sqlalchemy

### External Tools (detected at runtime, optional but recommended)
- **Compiler/build:** gcc, clang, cmake, meson, ninja, make, autotools
- **Static analysis:** clang-tidy, clang static analyzer, CodeQL, Semgrep, Cppcheck, Flawfinder
- **Runtime:** AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, Valgrind (optional)
- **Fuzzing (optional):** libFuzzer, AFL++

Run `vra doctor` to check which tools are available on your system. VRA degrades gracefully if a tool is missing — source-level analyzers and custom rules still run.

## Quick Start

```bash
# Initialize the workspace
vra init

# Check your environment
vra doctor

# Analyze a local project
vra analyze ./project

# Analyze with a specific profile
vra analyze ./project --profile deep

# List findings
vra findings

# Show a specific finding
vra finding show F-00001

# Generate an HTML report
vra report --format html
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `vra init` | Initialize the VRA workspace |
| `vra inspect <path>` | Inspect a project and show its metadata |
| `vra analyze <path>` | Run the full analysis pipeline (`--ai` enables AI narrative analysis, `--profile <p>` sets the profile). Shows live stage progress with percentages, per-analyzer status, and an enriched summary (severity/CWE/file distribution). |
| `vra findings` | List findings from the current analysis |
| `vra finding show <id>` | Show details of a specific finding |
| `vra rule list` | List all available security rules |
| `vra analyzer list` | List all available analyzers |
| `vra report` | Generate reports (html/markdown/json) |
| `vra doctor` | Check the environment for available tools |
| `vra clean` | Clean the VRA workspace |
| `vra test` | Run the test suite |

## Analysis Profiles

- **quick** — project inspection, clang, semgrep, cppcheck, custom rules
- **standard** (default) — quick + CodeQL + clang-tidy + source context + correlation
- **deep** — standard + advanced AST/CFG + dataflow + sanitizer build + additional rules

## Analyzer Support

VRA supports parallel execution of multiple analyzers through a plugin interface:

- clang-tidy
- clang static analyzer
- CodeQL
- Semgrep
- Cppcheck
- Flawfinder
- Sanitizers (ASan, UBSan, LSan)

Each analyzer follows a common interface: `available() → prepare() → run() → parse() → normalize()`. New analyzers can be added by implementing the `Analyzer` ABC and registering with the `AnalyzerRegistry`.

## Rule Engine

VRA includes a deterministic, source-level security rule engine independent of external scanners. Rules detect patterns like:

- **Memory:** use-after-free, double-free, buffer overflow, integer overflow, memory leak, sign conversion
- **Input:** unchecked length, unsafe deserialization, untrusted input, format string, command injection
- **Logic:** null dereference, unchecked return, resource lifecycle, race condition, TOCTOU, deep recursion

Rules use cautious language (e.g., "Potential use-after-free") and report confidence, never claiming confirmed vulnerabilities without runtime/sanitizer evidence.

## Finding Model

Every finding uses a unified schema regardless of source tool:

```json
{
  "id": "F-00127",
  "title": "Potential out-of-bounds write",
  "category": "memory-safety",
  "cwe": "CWE-787",
  "severity": "high",
  "confidence": 0.91,
  "source": { "file": "src/parser.c", "line": 481, "function": "parse_attribute" },
  "tools": ["codeql", "clang-analyzer"],
  "evidence": [],
  "dataflow": [],
  "call_chain": [],
  "reachability": {},
  "controllability": {},
  "impact": {}
}
```

Key concepts:
- **Severity** and **confidence** are kept separate — a finding can be high severity but low confidence.
- **Reachability** and **controllability** are reported as heuristic estimates, defaulting to `unknown` when uncertain.
- Every finding carries **evidence** and explicit **uncertainty**.

## Reports

VRA generates three report formats into `reports/`:
- **HTML** — the primary report, with a dashboard, finding list, and detail views
- **Markdown** — a concise human-readable summary
- **JSON** — machine-readable structured output

## Configuration

Configuration is read from `vra.yaml` in the working directory:

```yaml
analysis:
  profile: standard

analyzers:
  clang_tidy: true
  clang_analyzer: true
  codeql: true
  semgrep: true
  cppcheck: true

rules:
  memory:
    use_after_free: true
    double_free: true
    leak: true
    buffer_overflow: true

ai:
  enabled: false
  # provider: local
  # model: ""
  # model_command: ""   # optional external LLM invocation, e.g. "ollama run codellama"
```

## AI Integration (Optional)

AI is **disabled by default** and never required. Enable it per-run with
`vra analyze <path> --ai` or persistently via `vra.yaml` (`ai.enabled: true`).

When enabled, AI acts only as a presentation/reasoning layer on top of the
aggregated evidence:

- Executive summary with severity distribution
- Per-finding narrative (CWE, location, evidence, validation hints)
- Prioritized guidance and recommendations

The default **local** provider is a deterministic template engine (no external
dependency, fully offline). Optionally set `ai.model_command` to point at a
local LLM CLI (e.g. `ollama run codellama`) and VRA will invoke it with a
serialized findings payload, falling back to the template engine on any failure.

AI output is always tagged as an AI interpretation and never treated as
authoritative truth. AI never performs exploitation, payload generation, or
vulnerability confirmation.

## Development

```bash
pip install -e ".[dev]"
make test
make lint
```

## Testing

```bash
vra test
# or
python -m pytest tests/ -v
```

Tests cover:
- Fingerprinting and deduplication
- Correlation and merging
- Severity and confidence scoring
- Custom security rules (including false-positive suppression)
- Analyzer output parsing
- Project detection
- Full pipeline integration (with sample vulnerable and clean projects)

Sample vulnerable projects are in `tests/sample_projects/`, each with expected findings.

## Limitations

- Static analysis produces **potential** issues, not confirmed vulnerabilities.
- Reachability and controllability estimates are heuristic.
- Runtime confirmation requires sanitizer integration (not yet available in all profiles).
- VRA is an assistance tool — the final security judgment always rests with the human researcher.

---

> VRA is a vulnerability research assistance and evidence aggregation tool. It does not replace manual security review.
