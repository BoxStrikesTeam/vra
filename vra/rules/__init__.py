"""Rules package for VRA."""

from vra.rules.base import SecurityRule  # noqa: F401
from vra.rules.crypto import (  # noqa: F401
    crypto_misuse,
)
from vra.rules.input import (  # noqa: F401
    command_injection,
    format_string,
    path_hijack,
    unchecked_length,
    unsafe_deserialization,
    untrusted_input,
)
from vra.rules.logic import (  # noqa: F401
    null_deref,
    race_condition,
    resource_lifecycle,
    stack_recursion,
    toctou,
    unchecked_return,
)
from vra.rules.memory import (  # noqa: F401
    buffer_overflow,
    double_free,
    integer_overflow,
    leak,
    sign_conversion,
    use_after_free,
)
from vra.rules.registry import RuleRegistry  # noqa: F401

__all__ = [
    "SecurityRule",
    "RuleRegistry",
    "crypto_misuse",
    "buffer_overflow",
    "double_free",
    "integer_overflow",
    "leak",
    "sign_conversion",
    "use_after_free",
    "null_deref",
    "race_condition",
    "resource_lifecycle",
    "stack_recursion",
    "toctou",
    "unchecked_return",
    "unchecked_length",
    "unsafe_deserialization",
    "untrusted_input",
    "format_string",
    "command_injection",
    "path_hijack",
]
