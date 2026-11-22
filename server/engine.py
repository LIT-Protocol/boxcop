"""Deterministic, explainable decisions about reported agent actions.

This module never executes an action. It evaluates what a pre-action hook
reports: a shell command, or a native file read or write.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from threading import RLock
from time import perf_counter
from uuid import uuid4

from .classify import sanitize_metadata
from .classification import ContentClassifier
from .workflow_context import WorkflowContextStore
from .commands import (
    _credential_path, credential_file_egress, credential_file_reference, download_then_execute, has_network_tool,
    remote_execution,
)
from .models import Decision, EventInput, Record
from .store import NOT_RETAINED
from .supply_chain import command_findings
from .skill_security import findings as skill_findings

# The generic email/phone "pii" label is excluded: user@host is ordinary
# ssh/scp/git syntax. SSNs and the other labels still count.
SENSITIVE = frozenset({"secret", "private-key", "ssn", "medical", "hr-sensitive", "restricted-business"})
# Invisible formatting/control characters can make a command differ from its
# visible text. Stop on uncertainty; do not normalize and execute it.
AMBIGUOUS_CONTROLS = "​⁠﻿‪‫‬‭‮⁦⁧⁨⁩\x08\x1b\r"


class Engine:
    def __init__(self, store, clock=None, *, classifier=None):
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.classifier = classifier or ContentClassifier()
        self.workflow_context = WorkflowContextStore()
        self._lock = RLock()

    def evaluate(self, event: EventInput, *, raw_command=None, scoped=False) -> Record:
        # Serialize the decision and its audit save.
        with self._lock:
            return self._evaluate(event, raw_command, scoped)

    def _evaluate(self, event: EventInput, raw_command, scoped) -> Record:
        start = perf_counter()
        created_at = self.clock().astimezone(timezone.utc).isoformat()
        labels = self.classifier.labels(event.content)
        sensitive = bool(SENSITIVE.intersection(labels))
        enabled = {p["id"] for p in self.store.policies() if p["enabled"]}
        matches = []

        def match(policy_id, condition, action, score, reason):
            if condition and policy_id in enabled:
                matches.append((policy_id, action, score, reason))

        is_command = event.action == "command"
        if not is_command:
            for finding in skill_findings(event.content):
                match(finding["id"], True, "block", 96, finding["description"])
            match('native-sensitive-file', _credential_path(event.destination, include_dotenv=True) or sensitive,
                  'block', 98, 'A native file action targets a conventional credential store or contains recognizable sensitive data. Use a redacted fixture or a non-sensitive file.')
        else:
            match('ambiguous-command-text', any(c in event.content for c in AMBIGUOUS_CONTROLS),
                  'warn', 75, 'The command contains invisible formatting or terminal control characters. Remove them and check the visible command before retrying; no command was executed.')
            for finding in command_findings(event.content):
                match(finding.policy, True, 'warn' if finding.policy in {'unsupported-runtime', 'unresolved-runtime-version'} else 'block', 94, finding.reason)
            match("sensitive-local", sensitive, "warn", 50, "Recognizable sensitive content is included in a command.")
            match("command-sensitive-egress", sensitive and has_network_tool(event.content), "block", 98, "A command combines recognizable sensitive content with a network tool. The command text cannot establish that the content stays local.")
            match("remote-shell", remote_execution(event.content), "block", 99, "A recognizable fetch/decode-to-execution heuristic matched; no command was executed.")
            match("download-then-exec", download_then_execute(event.content), "warn", 70, "A download-then-execute heuristic matched; check the sequence. No command was executed.")
            credential_egress = "credential-file-egress" in enabled and credential_file_egress(event.content)
            match("credential-file-egress", credential_egress, "block", 98, "A command names a conventional credential store (for example ~/.aws/credentials, an SSH private key, or .env) together with a network tool. Nothing was read, sent, or executed.")
            match("credential-file-access", not credential_egress and credential_file_reference(event.content, include_dotenv=False), "warn", 65, "A command reads a conventional credential store; confirm this is expected. Nothing was read or executed.")
        strength = {"allow": 0, "warn": 1, "block": 2}
        strongest = max(matches, key=lambda item: (strength[item[1]], item[2])) if matches else None
        action = strongest[1] if strongest else "allow"
        # Metadata is untrusted too; never interpolate original fields into reasons.
        sanitized = event.model_dump()
        # Match the full sanitized content with equivalent whitespace, without
        # normalizing unrelated metadata. This is not fragment/encoding removal.
        content_parts = sanitize_metadata(event.content, truncate=False).split()
        content_copy = re.compile(r"\s+".join(map(re.escape, content_parts))) if content_parts else None
        for field in ("session_id", "app", "source", "destination", "declared_intent"):
            value = sanitized[field]
            if event.content:
                # Preserve raw suppression before context-sensitive sanitization.
                value = value.replace(event.content, NOT_RETAINED)
            value = sanitize_metadata(value)
            if content_copy is not None:
                value = content_copy.sub(NOT_RETAINED, value)[:1024]
            sanitized[field] = value
        for field in ("session_id", "app"):
            if not sanitized[field].strip():
                sanitized[field] = "[empty after sanitizing]"
        sanitized["content"] = NOT_RETAINED
        summary = {
            "allow": "No enabled rule matched; this is not a safety guarantee.",
            "warn": "An enabled rule flags this action.",
            "block": "An enabled rule blocks this action.",
        }[action]
        record = Record(id=str(uuid4()), created_at=created_at, event=EventInput(**sanitized), decision=Decision(
            action=action, risk_score=float(strongest[2]) if strongest else 0.0,
            summary=summary, reasons=[item[3] for item in matches] or ["Only reported actions and recognizable patterns are evaluated."],
            policy_ids=[item[0] for item in matches], labels=labels,
            latency_ms=round((perf_counter() - start) * 1000, 3),
        ))
        if raw_command is not None and is_command and action != 'allow':
            # Preserve lines for inspection. Only offer approval when every character
            # is visible and the displayed command is identical to the original.
            display = '\n'.join(sanitize_metadata(line, truncate=False) for line in raw_command.split('\n'))
            if sensitive:
                display = '[Command withheld because it contains sensitive data]'
            fingerprint = None
            if (scoped and display == raw_command and all(c.isprintable() or c == '\n' for c in display)
                    and set(record.decision.policy_ids) <= {'remote-shell', 'download-then-exec'}):
                identity = [event.model_dump(), raw_command, sorted(record.decision.policy_ids)]
                fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            self.store.save(record, command=display, fingerprint=fingerprint)
        else:
            self.store.save(record)
        return record
