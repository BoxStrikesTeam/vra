"""Structural (rule-based) validation layer for candidate findings.

This is the first FP-reduction stage. Detection rules flag candidates; these
validators re-examine each candidate's source context, dataflow and
controllability and return a :class:`ValidationOutcome` that the orchestrator
uses to downgrade confidence or mark the finding as a likely false positive.
"""

from __future__ import annotations

from vra.rules.validation.alloc_overflow import AllocOverflowValidator
from vra.rules.validation.array_index import ArrayIndexValidator
from vra.rules.validation.base import (
    SecurityValidator,
    ValidationEngine,
    ValidationOutcome,
)
from vra.rules.validation.buffer_overflow import BufferOverflowValidator
from vra.rules.validation.command_injection import CommandInjectionValidator
from vra.rules.validation.crypto_misuse import CryptoMisuseValidator
from vra.rules.validation.format_string import FormatStringValidator
from vra.rules.validation.input_validation import InputValidationValidator
from vra.rules.validation.integer_overflow import IntegerOverflowValidator
from vra.rules.validation.memory_leak import MemoryLeakValidator
from vra.rules.validation.null_deref import NullDerefValidator
from vra.rules.validation.recursion import RecursionValidator
from vra.rules.validation.resource_result import ResourceResultValidator
from vra.rules.validation.use_after_free import UseAfterFreeValidator
from vra.rules.validation.weak_random import WeakRandomValidator

ALL_VALIDATORS: list[SecurityValidator] = [
    MemoryLeakValidator(),
    NullDerefValidator(),
    ArrayIndexValidator(),
    BufferOverflowValidator(),
    CommandInjectionValidator(),
    AllocOverflowValidator(),
    UseAfterFreeValidator(),
    CryptoMisuseValidator(),
    IntegerOverflowValidator(),
    FormatStringValidator(),
    ResourceResultValidator(),
    WeakRandomValidator(),
    RecursionValidator(),
    InputValidationValidator(),
]


def build_validation_engine(
    validators: list[SecurityValidator] | None = None,
    strict: bool = False,
) -> ValidationEngine:
    engine = ValidationEngine()
    for v in validators or ALL_VALIDATORS:
        if hasattr(v, "strict"):
            v.strict = strict
        engine.add(v)
    return engine


__all__ = [
    "SecurityValidator",
    "ValidationEngine",
    "ValidationOutcome",
    "build_validation_engine",
    "ALL_VALIDATORS",
]
