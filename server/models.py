"""Strict wire models. Roles and intent are caller declarations, not identities."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .skill_security import POLICIES as SKILL_POLICIES

Metadata = Annotated[str, Field(max_length=1024)]
Action = Literal["allow", "warn", "block"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EventInput(StrictModel):
    session_id: Annotated[str, Field(min_length=1, max_length=1024)]
    actor: Literal["human", "agent"]
    role: Literal["engineering", "hr", "finance"]
    action: Literal["copy", "paste", "upload", "command", "navigate", "read", "write"]
    app: Annotated[str, Field(min_length=1, max_length=1024, pattern=r"\S")]
    source: Metadata = ""
    destination: Metadata = ""
    content: Annotated[str, Field(max_length=32768)] = ""
    declared_intent: Metadata = ""
    synthetic: bool = False


class Decision(StrictModel):
    action: Action
    risk_score: float
    summary: str
    reasons: list[str]
    policy_ids: list[str]
    labels: list[str]
    redacted_content: str
    latency_ms: float
    context_event_ids: list[str]
    engine: Literal["rules+sequence"] = "rules+sequence"


class Record(StrictModel):
    id: str
    created_at: str
    synthetic: bool
    event: EventInput
    decision: Decision


class PolicyUpdate(StrictModel):
    enabled: bool


class SemanticInput(StrictModel):
    text: Annotated[str, Field(min_length=1, max_length=32768)]


class EmptyInput(StrictModel):
    pass


# Static, explainable rules only; descriptions never incorporate caller content.
POLICIES = [
    *SKILL_POLICIES,
    *[{"id": key, "name": name, "description": description, "action": action} for key, name, description, action in [
        ("known-malicious-package", "Known malicious package", "Hold literal installation of confirmed malicious releases in the reviewed offline advisory snapshot.", "block"),
        ("vulnerable-runtime", "Known vulnerable runtime", "Hold literal installation of upstream PHP releases predating reviewed security fixes.", "block"),
        ("unsupported-runtime", "Unsupported runtime", "Review obsolete PHP branches; maintained vendor backports require separate assessment.", "warn"),
        ("unresolved-runtime-version", "Unresolved runtime patch status", "Review PHP branch aliases and vendor versions without claiming a known vulnerability.", "warn"),
    ]],
    {"id": "native-sensitive-file", "name": "Native sensitive file access", "description": "Block reported native reads/writes of conventional credential paths, and supplied read/write content containing recognizable sensitive data. Path preflight is not OS containment.", "action": "block"},
    {"id": "secret-egress", "name": "Credential egress", "description": "Block recognizable credentials or private keys pasted/uploaded to external or unknown destinations.", "action": "block"},
    {"id": "sensitive-egress", "name": "Sensitive information egress", "description": "Block recognizable medical, personnel or explicitly restricted financial deal details sent to external or unknown destinations.", "action": "block"},
    {"id": "high-risk-pii", "name": "High-risk personal data", "description": "Block SSN-like identifiers sent to external or unknown destinations.", "action": "block"},
    {"id": "pii-egress", "name": "Personal data caution", "description": "Warn on recognizable personal contact information leaving the local workbench.", "action": "warn"},
    {"id": "sensitive-local", "name": "Sensitive local content", "description": "Warn when recognizable sensitive content is copied, sent locally, or handled in a command even with an unknown destination.", "action": "warn"},
    {"id": "ambiguous-command-text", "name": "Invisible command text", "description": "Review commands and supported terminal pastes containing zero-width spaces, bidi controls or terminal control characters. Text-editor/browser prose is outside this command rule.", "action": "warn"},
    {"id": "remote-shell", "name": "Remote execution pattern", "description": "Block recognizable fetch/decode-to-execution patterns. This is a heuristic, not a shell parser.", "action": "block"},
    {"id": "download-then-exec", "name": "Download followed by execution", "description": "Warn on recognizable download-then-execute sequences. This is a heuristic, not a shell parser.", "action": "warn"},
    {"id": "command-sensitive-egress", "name": "Sensitive command network egress", "description": "Block recognizable sensitive content with a network tool in a command regardless of declared destination. This is a heuristic, not a shell parser.", "action": "block"},
    {"id": "credential-file-egress", "name": "Credential store egress", "description": "Block commands naming a conventional credential store (cloud credentials, SSH private keys, .netrc, .env) together with a network tool. Identity use such as ssh -i is excluded. Heuristic, not a shell parser.", "action": "block"},
    {"id": "credential-file-access", "name": "Credential store access", "description": "Warn when a command reads a conventional credential store locally; .env alone is excluded as routine development. Heuristic, not a shell parser.", "action": "warn"},
    {"id": "destructive-command", "name": "Catastrophic delete pattern", "description": "For human input only, block recursive forced rm of root, home, current/parent, shallow system paths, or variable paths that could expand to root; heuristic, not a shell parser.", "action": "block"},
    {"id": "recursive-delete", "name": "Recursive delete review", "description": "For human input only, warn on recursive forced rm of ordinary targets such as build directories; heuristic, not a shell parser.", "action": "warn"},
    {"id": "role-shell", "name": "Declared-role mismatch", "description": "Warn for shell/interpreter commands outside the declared engineering role; declared role is not authenticated identity.", "action": "warn"},
    {"id": "sensitive-lineage", "name": "Sensitive copy to external paste", "description": "Correlate exact-content pastes with copies of sensitive content, or from a declared sensitive source such as an HR system, in one declared session within five minutes regardless of synthetic label. Bounded in-memory history resets on restart; fingerprints are never persisted.", "action": "block"},
]

# Review configuration lives in the approval inbox/team policy, not the rule toggles.
REVIEW_POLICIES = [{"id": "human-review-required", "name": "Human approval required",
                   "description": "A configured local or team review rule holds a covered agent action until one-time human approval.",
                   "action": "block"}]
