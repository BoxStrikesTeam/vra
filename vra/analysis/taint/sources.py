"""Taint source definitions for VRA.

A *source* is a construct that introduces attacker-controlled data into the
program, e.g. process arguments, environment variables, file/socket reads, or
standard input. When tainted data reaches a sensitive sink we classify input
controllability.

This is a *practical* taint model: it recognises common input APIs and the
variables they populate. It is intentionally conservative about guarantees and
does not attempt full alias/inter-procedural value analysis.
"""

from __future__ import annotations

import re

# --- Constant identifiers that are always treated as tainted ----------------
# These names typically hold attacker-influenced data at the point of use.
SOURCE_IDENTIFIER_RE = re.compile(
    r"\b(argv|argc|envp|optarg|user_input|user_data|input|data|cmd|command|shell|"
    r"username|password|token|param|arg|buf|buffer|src|request|msg|payload|"
    r"user_cmd|user_arg|s|str)\b",
    re.I,
)

# --- Function calls that return tainted data --------------------------------
# format: call name -> input surface hint
SOURCE_CALLS = {
    "getenv": "environment",
    "getopt": "cli",
    "getopt_long": "cli",
    "read": "filesystem",
    "readlink": "filesystem",
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "scanf": "stdin",
    "fscanf": "filesystem",
    "getchar": "stdin",
    "gets": "stdin",
    "fgets": "filesystem",
    "getline": "filesystem",
    "fread": "filesystem",
}

# --- API families that imply our project parses network/external input -------
# If a function name contains these, treat its parameters as tainted on entry.
NETWORKISH_HINT = re.compile(
    r"(parse|handler|dispatch|process|handle|event|decode|unmarshal|deserialize|"
    r"read_pkt|frombytes|from_buffer|decode_message)", re.I
)


def surface_for_identifier(name: str) -> str:
    """Return a coarse attack-surface label for a tainted identifier."""
    low = name.lower()
    if "cmd" in low or "command" in low or "shell" in low or "exec" in low:
        return "cli"
    if "tok" in low or "pass" in low or "secret" in low or "cred" in low:
        return "configuration"
    if any(x in low for x in ("input", "data", "buffer", "buf", "payload", "msg")):
        return "network"
    if low in ("argv", "argc", "optarg", "param", "arg", "user_arg"):
        return "cli"
    return "unknown"


def looks_like_source_call(name: str) -> bool:
    return name in SOURCE_CALLS


def source_hint_for_call(name: str) -> str | None:
    return SOURCE_CALLS.get(name)
