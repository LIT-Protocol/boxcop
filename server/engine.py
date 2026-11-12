"""Deterministic, explainable decisions. This module never executes an event."""
from datetime import datetime, timezone
import re
from threading import RLock
from time import monotonic, perf_counter
from uuid import uuid4

from .classify import destination_kind, redact, sanitize_metadata, source_labels
from .classification import ContentClassifier
from .workflow_context import WorkflowContextStore
from .commands import (
    _credential_path, credential_file_egress, credential_file_reference, download_then_execute, has_network_tool,
    recursive_delete, remote_execution,
)
from .lineage import LineageTracker
from .models import Decision, EventInput, Record
from .store import NOT_RETAINED
from .supply_chain import command_findings
from .skill_security import findings as skill_findings

SHELL_COMMAND = re.compile(r"\b(?:python[23]?|node|ruby|perl|bash|sh|zsh|curl|wget|rm|sudo|powershell|cmd)\b", re.I)
SENSITIVE = frozenset({"secret", "private-key", "pii", "ssn", "medical", "hr-sensitive", "restricted-business"})
# The generic email/phone "pii" label is excluded for commands: user@host is
# ordinary ssh/scp/git syntax. SSNs and the other labels still count.
COMMAND_SENSITIVE = SENSITIVE - {"pii"}


TERMINAL_APPS = frozenset({'com.apple.Terminal', 'com.googlecode.iterm2', 'com.mitchellh.ghostty'})


class Engine:
    def __init__(self, store, clock=None, *, monotonic_clock=None, classifier=None, action_gate=None):
        self.store = store
        self.action_gate = action_gate
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic_clock = monotonic_clock or monotonic
        self.classifier = classifier or ContentClassifier()
        self.workflow_context = WorkflowContextStore()
        self._lineage = LineageTracker()
        self._lock = RLock()

    def evaluate(self, event: EventInput, *, retain_preview: bool = False) -> Record:
        # This permission is internal, never part of the caller's wire model.
        if retain_preview and not event.synthetic:
            raise ValueError("Preview retention requires an internal synthetic event")
        # Serialize context lookup, successful audit save, and lineage update.
        with self._lock:
            return self._evaluate(event, retain_preview=retain_preview)

    def _evaluate(self, event: EventInput, *, retain_preview: bool) -> Record:
        start = perf_counter()
        created_at = self.clock().astimezone(timezone.utc).isoformat()
        now = self.monotonic_clock()
        labels = self.classifier.labels(event.content) + source_labels(event.source)
        sensitive = bool(SENSITIVE.intersection(labels))
        destination = destination_kind(event.destination)
        egress = event.action in {"paste", "upload", "navigate"} and destination != "local"
        # Lookup also expires stale entries on non-copy/paste events. Caller
        # synthetic labels deliberately cannot partition or weaken correlation.
        copies = self._lineage.lookup(event.session_id, event.content, now)
        context_ids = copies if event.action in {"paste", "upload"} else []
        enabled = {p["id"] for p in self.store.policies() if p["enabled"]}
        matches = []

        def match(policy_id, condition, action, score, reason):
            if condition and policy_id in enabled:
                matches.append((policy_id, action, score, reason))

        if event.actor == "agent" and event.action in {"read", "write"}:
            for finding in skill_findings(event.content):
                match(finding["id"], True, "block", 96, finding["description"])

        is_command = event.action == "command"
        executable_input = is_command or event.action == 'paste' and event.app in TERMINAL_APPS
        # Invisible formatting/control characters can make executable input differ
        # from its visible review. Hold uncertainty; do not normalize and execute it.
        ambiguous_controls = "\u200b\u2060\ufeff\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\x08\x1b\r"
        match('ambiguous-command-text', executable_input and any(c in event.content for c in ambiguous_controls),
              'warn', 75, 'Executable input contains invisible formatting or terminal control characters. Remove them and review the visible command before retrying; no command was executed.')
        if executable_input:
            for finding in command_findings(event.content):
                match(finding.policy, True, 'warn' if finding.policy in {'unsupported-runtime', 'unresolved-runtime-version'} else 'block', 94, finding.reason)
        match('native-sensitive-file', event.action in {'read', 'write'} and (
            _credential_path(event.destination, include_dotenv=True) or bool(COMMAND_SENSITIVE.intersection(labels))),
            'block', 98, 'A native file action targets a conventional credential store or contains recognizable sensitive data. Use a redacted fixture or a non-sensitive file.')
        match("secret-egress", egress and "secret" in labels, "block", 98, "Recognizable credential or private key would leave the local environment.")
        match("sensitive-egress", egress and bool({"medical", "hr-sensitive", "restricted-business"}.intersection(labels)), "block", 95, "Recognizable medical, personnel or explicitly restricted business information is headed to an external or unknown destination.")
        match("high-risk-pii", egress and "ssn" in labels, "block", 92, "An SSN-like personal identifier would leave the local environment.")
        match("pii-egress", egress and "pii" in labels and "ssn" not in labels, "warn", 60, "Contact information may identify a person; confirm the destination and consent.")
        command_sensitive = is_command and bool(COMMAND_SENSITIVE.intersection(labels))
        # Deletion checks apply to human executable input, not agent actions.
        deletion = recursive_delete(event.content) if executable_input and event.actor != "agent" else None
        match("sensitive-local", command_sensitive or not is_command and sensitive and (event.action == "copy" or destination == "local"), "warn", 50, "Recognizable sensitive content is being copied, handled locally, or included in a command.")
        match("command-sensitive-egress", command_sensitive and has_network_tool(event.content), "block", 98, "A command combines recognizable sensitive content with a network-tool heuristic; declared destination cannot establish that it stays local.")
        match("remote-shell", executable_input and remote_execution(event.content), "block", 99, "A recognizable fetch/decode-to-execution heuristic matched; no command was executed.")
        match("download-then-exec", executable_input and download_then_execute(event.content), "warn", 70, "A download-then-execute heuristic matched; review the sequence. No command was executed.")
        credential_egress = executable_input and "credential-file-egress" in enabled and credential_file_egress(event.content)
        match("credential-file-egress", credential_egress, "block", 98, "A command names a conventional credential store (for example ~/.aws/credentials, an SSH private key, or .env) together with a network tool. Nothing was read, sent, or executed.")
        match("credential-file-access", executable_input and not credential_egress and credential_file_reference(event.content, include_dotenv=False), "warn", 65, "A command reads a conventional credential store; confirm this is expected. Nothing was read or executed.")
        match("destructive-command", deletion == "catastrophic", "block", 99, "Recursive forced deletion targets root, home, the current/parent directory, a system path, or a variable that could expand to root; no command was executed.")
        match("recursive-delete", deletion == "routine", "warn", 60, "Recursive forced deletion detected; confirm the target before running it. No command was executed.")
        match("role-shell", is_command and event.role != "engineering" and bool(SHELL_COMMAND.search(event.content)), "warn", 55, "Shell or interpreter use differs from the declared role; the declared role is not authenticated identity.")
        match("sensitive-lineage", egress and bool(context_ids), "block", 97, "An ephemeral exact-content match links this paste to a copy of sensitive content, or from a declared sensitive source, in this session within five minutes.")
        strength = {"allow": 0, "warn": 1, "block": 2}
        strongest = max(matches, key=lambda item: (strength[item[1]], item[2])) if matches else None
        action = strongest[1] if strongest else "allow"
        # Internal cooperative hook gate runs only after existing rules allow.
        # Commit the final decision to the same audit used by reporting.
        if action == "allow" and self.action_gate is not None:
            permitted, reason = self.action_gate()
            if not permitted:
                strongest = ("human-review-required", "block", 0, reason)
                matches.append(strongest)
                action = "block"
        preview = redact(sanitize_metadata(event.content))[:1024] if retain_preview else NOT_RETAINED
        # Metadata is untrusted too; never interpolate original fields into reasons.
        sanitized = event.model_dump()
        # Match the full sanitized content with equivalent whitespace, without
        # normalizing unrelated metadata. This is not fragment/encoding removal.
        content_parts = sanitize_metadata(event.content, truncate=False).split() if not retain_preview else []
        content_copy = re.compile(r"\s+".join(map(re.escape, content_parts))) if content_parts else None
        for field in ("session_id", "app", "source", "destination", "declared_intent"):
            value = sanitized[field]
            if not retain_preview and event.content:
                # Preserve raw suppression before context-sensitive sanitization.
                value = value.replace(event.content, NOT_RETAINED)
            value = sanitize_metadata(value)
            if content_copy is not None:
                value = content_copy.sub(NOT_RETAINED, value)[:1024]
            sanitized[field] = value
        for field in ("session_id", "app"):
            if not sanitized[field].strip():
                sanitized[field] = "[empty after sanitizing]"
        sanitized["content"] = preview
        summary = {
            "allow": "No enabled narrow rule matched; this is not a safety guarantee.",
            "warn": "Review required by an enabled contextual policy.",
            "block": "An enabled deterministic policy blocks this action.",
        }[action]
        record = Record(id=str(uuid4()), created_at=created_at, synthetic=event.synthetic, event=EventInput(**sanitized), decision=Decision(
            action=action, risk_score=float(strongest[2]) if strongest else 0.0,
            summary=summary, reasons=[item[3] for item in matches] or ["Only explicit submitted events and recognizable patterns are evaluated."],
            policy_ids=[item[0] for item in matches], labels=labels,
            redacted_content=preview, latency_ms=round((perf_counter() - start) * 1000, 3),
            context_event_ids=context_ids,
        ))
        self.store.save(record, retain_preview=retain_preview)
        if event.action == "copy":
            # Provenance: an innocuous-looking copy from a sensitive declared source
            # is remembered as sensitive, so the same text pasted later is blocked.
            self._lineage.remember(event.session_id, event.content, record.id, now,
                                   sensitive=sensitive or "sensitive-source" in labels)
        return record
