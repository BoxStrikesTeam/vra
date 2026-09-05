# Custom Rules

VRA ships deterministic source-level security rules under `vra/rules/`.
To add your own rule:

1. Create a module under `vra/rules/<category>/` (e.g. `vra/rules/input/`).
2. Subclass `SecurityRule`, decorate with `@RuleRegistry.register`, and
   implement `analyze(context)` returning a list of `Finding`.
3. Import the new module in the matching `__init__.py` so it is registered
   on package import.

See `examples/custom_rule.py` for a complete, working template.

Rules must use cautious language and report a confidence score; a rule must
never claim a finding is a confirmed vulnerability based on static evidence alone.
