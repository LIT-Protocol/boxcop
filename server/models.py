"""Strict models for reported agent actions and the decisions made about them."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .skill_security import POLICIES as SKILL_POLICIES

Metadata = Annotated[str, Field(max_length=1024)]
Action = Literal["allow", "warn", "block"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EventInput(StrictModel):
    """One action reported by a pre-action hook. `app` is the reporting harness."""
    session_id: Annotated[str, Field(min_length=1, max_length=1024)]
    action: Literal["command", "read", "write"]
    app: Annotated[str, Field(min_length=1, max_length=1024, pattern=r"\S")]
    source: Metadata = ""
    destination: Metadata = ""
    content: Annotated[str, Field(max_length=32768)] = ""
    declared_intent: Metadata = ""


class Decision(StrictModel):
    action: Action
    risk_score: float
    summary: str
    reasons: list[str]
    policy_ids: list[str]
    labels: list[str]
    latency_ms: float
    engine: Literal["rules"] = "rules"


class Record(StrictModel):
    id: str
    created_at: str
    event: EventInput
    decision: Decision


# Static, explainable rules only; descriptions never incorporate caller content.
POLICIES = [
    *SKILL_POLICIES,
    *[{"id": key, "name": name, "description": description, "action": action} for key, name, description, action in [
        ("known-malicious-package", "Known malicious package", "Block literal installation of confirmed malicious releases in the reviewed offline advisory snapshot.", "block"),
        ("vulnerable-runtime", "Known vulnerable runtime", "Block literal installation of upstream PHP releases predating reviewed security fixes.", "block"),
        ("unsupported-runtime", "Unsupported runtime", "Review obsolete PHP branches; maintained vendor backports require separate assessment.", "warn"),
        ("unresolved-runtime-version", "Unresolved runtime patch status", "Review PHP branch aliases and vendor versions without claiming a known vulnerability.", "warn"),
    ]],
    {"id": "native-sensitive-file", "name": "Sensitive file access", "description": "Block reported file reads and writes that target conventional credential paths, and writes whose content contains recognizable sensitive data. A path check before the action is not OS containment.", "action": "block"},
    {"id": "sensitive-local", "name": "Sensitive content in a command", "description": "Warn when a command includes recognizable sensitive content.", "action": "warn"},
    {"id": "ambiguous-command-text", "name": "Invisible command text", "description": "Review commands containing zero-width spaces, bidi controls or terminal control characters.", "action": "warn"},
    {"id": "remote-shell", "name": "Remote execution pattern", "description": "Block recognizable fetch/decode-to-execution patterns. This is a heuristic, not a shell parser.", "action": "block"},
    {"id": "download-then-exec", "name": "Download followed by execution", "description": "Warn on recognizable download-then-execute sequences. This is a heuristic, not a shell parser.", "action": "warn"},
    {"id": "command-sensitive-egress", "name": "Sensitive content sent by a command", "description": "Block recognizable sensitive content combined with a network tool in a command. This is a heuristic, not a shell parser.", "action": "block"},
    {"id": "credential-file-egress", "name": "Credential store egress", "description": "Block commands naming a conventional credential store (cloud credentials, SSH private keys, .netrc, .env) together with a network tool. Identity use such as ssh -i is excluded. Heuristic, not a shell parser.", "action": "block"},
    {"id": "credential-file-access", "name": "Credential store access", "description": "Warn when a command reads a conventional credential store locally; .env alone is excluded as routine development. Heuristic, not a shell parser.", "action": "warn"},
]
