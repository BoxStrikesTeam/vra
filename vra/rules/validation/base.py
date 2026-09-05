"""Base classes for structural (rule-based) finding validation.

The detection rules in ``vra.rules.*`` flag *candidate* issues. Validators are
a second, intent-specific layer: they re-examine a finding's source context,
dataflow, call chain and controllability to decide whether the candidate is
structurally plausible (``CONFIRMED``), needs human review (``SUSPICIOUS``) or
is likely a false positive (``LIKELY_FP``).

Validators never drop findings silently; they annotate them so the pipeline can
downgrade confidence and set ``FindingStatus.LIKELY_FALSE_POSITIVE``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("rules.validation")


@dataclass
class ValidationOutcome:
    """The result of validating a single finding."""

    verdict: ValidationResult = ValidationResult.SUSPICIOUS
    reason: str = ""
    indicators: list[str] = field(default_factory=list)


class SecurityValidator(ABC):
    """Base class for a structural validator.

    Subclasses declare which finding categories/CWEs they understand and
    implement :meth:`validate`.
    """

    name: str = "base"
    #: finding categories this validator handles (e.g. "memory", "input")
    categories: tuple[str, ...] = ()
    #: CWEs handled (e.g. "CWE-401", "CWE-120")
    cwes: tuple[str, ...] = ()
    #: map from concrete findings of other CWEs
    handles_cwe: tuple[str, ...] = ()

    def applies_to(self, finding: Finding) -> bool:
        """Whether this validator understands the finding.

        CWE is the primary key: every validator declares the CWEs it handles and
        matches on them. Category is only a fallback for (currently theoretical)
        category-driven validators that declare no CWEs, which keeps category
        sets that overlap between validators from causing double-matching.
        """
        if self.cwes and finding.cwe in self.cwes:
            return True
        if not self.cwes and finding.category in self.categories:
            return True
        return False

    @abstractmethod
    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome: ...


class ValidationEngine:
    """Routes findings to the validators that understand them."""

    def __init__(self, validators: list[SecurityValidator] | None = None):
        self._validators: list[SecurityValidator] = validators or []

    def add(self, validator: SecurityValidator) -> None:
        self._validators.append(validator)

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        """Run all applicable validators and merge their verdicts.

        Verdict precedence (most conservative wins): ``LIKELY_FP`` >
        ``SUSPICIOUS`` > ``CONFIRMED``. If no validator applies, the finding
        remains ``SUSPICIOUS`` (needs human review) with no FP indicators set.
        """
        applicable = [v for v in self._validators if v.applies_to(finding)]
        if not applicable:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="No structural validator applies; manual review required.",
            )

        outcomes = []
        for v in applicable:
            try:
                outcomes.append(v.validate(finding, source_content, source_dir))
            except Exception:  # pragma: no cover - resilience
                log.debug("Validator %s failed for %s", v.name, finding.id, exc_info=True)
        if not outcomes:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Validators did not produce a verdict; manual review required.",
            )

        rank = {
            ValidationResult.LIKELY_FP: 3,
            ValidationResult.SUSPICIOUS: 2,
            ValidationResult.CONFIRMED: 1,
        }
        outcomes.sort(key=lambda o: rank.get(o.verdict, 0), reverse=True)
        top = outcomes[0]
        indicators = []
        for o in outcomes:
            indicators.extend(o.indicators)
        # De-duplicate indicator text.
        seen = set()
        unique = []
        for s in indicators:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        reasons = "; ".join(f"{v.name}: {o.reason}" for v, o in zip(applicable, outcomes))
        return ValidationOutcome(
            verdict=top.verdict,
            reason=reasons,
            indicators=unique,
        )
