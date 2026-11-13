"""Offline skill heuristics inspired by NVIDIA SkillSpector's threat categories.

Original rules, not a vendored scanner. Never executes, imports or fetches content.
Findings contain fixed explanations only, never excerpts of inspected files.
"""
import os
from pathlib import Path
import re
import stat

from .commands import credential_file_egress, remote_execution, download_then_execute

MAX_BYTES = 20000
MAX_FILES = 256
MAX_TOTAL_BYTES = 1024 * 1024

POLICIES = [
    {'id': key, 'name': name, 'description': reason, 'action': 'block'}
    for key, name, reason in [
        ('skill-instruction-override', 'Agent instruction override', 'Agent input contains a recognizable instruction to override higher-priority rules or disable safeguards. Check the source before use.'),
        ('skill-concealed-action', 'Concealed agent action', 'Agent input asks to conceal actions from the user. Check the source before use.'),
        ('skill-credential-egress', 'Skill credential exfiltration', 'Agent input combines a credential-store reference and a network tool. Check the source before use.'),
        ('skill-remote-execution', 'Skill remote execution', 'Agent input contains a fetch/decode-to-execution or download-then-execute pattern. Check the source before use.'),
    ]
]
OVERRIDE = re.compile(
    r'\b(?:ignore|disregard|override|bypass)\s+(?:(?:all|the|any|your)\s+)?'
    r'(?:previous|prior|system|developer|safety|security)\s+(?:instructions?|prompts?|rules?|polic(?:y|ies)|checks?)\b'
    r'|\bdisable\s+(?:(?:all|the|your)\s+)?(?:security|safety|audit)\s+(?:checks?|logging|guards?|hooks?)\b', re.I)
CONCEAL = re.compile(
    r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user\b"
    r'|\bhide\s+(?:this|these|the)\s+(?:actions?|activity|commands?|uploads?)\s+from\s+(?:the\s+)?user\b', re.I)


def findings(content):
    conditions = [OVERRIDE.search(content), CONCEAL.search(content),
                  credential_file_egress(content),
                  remote_execution(content) or download_then_execute(content)]
    return [dict(policy) for policy, condition in zip(POLICIES, conditions) if condition]


def instruction_path(path):
    p = Path(path)
    return p.name.lower() in {'skill.md', 'agents.md', 'claude.md'} or 'skills' in p.parts or '.skills' in p.parts


def read_text(path):
    """Bounded regular-file read. Refuse links, devices and invalid UTF-8."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('not a regular file')
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('file exceeds scan bound')
    text = raw.decode('utf-8')
    if '\x00' in text:
        raise ValueError('binary file')
    return text


def scan(root):
    """Explicit local bundle scan; unsupported/unreadable entries mean incomplete.

    No symlinks followed. File names/content are omitted from the report to avoid
    retaining secrets; findings identify files by their traversal ordinal only.
    """
    root = Path(root)
    records, errors = [], []
    count = total = 0
    pending = [root]
    while pending:
        path = pending.pop()
        count += 1
        if count > MAX_FILES:
            errors.append('entry_limit')
            break
        try:
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                # Bound enumeration as well as file reads, including empty dirs.
                with os.scandir(path) as entries:
                    for entry in entries:
                        if len(pending) + count >= MAX_FILES:
                            errors.append('entry_limit')
                            break
                        pending.append(Path(entry.path))
                continue
            content = read_text(path)
            total += len(content.encode('utf-8'))
            if total > MAX_TOTAL_BYTES:
                errors.append('byte_limit')
                break
            for finding in findings(content):
                records.append({'entry': count, **finding})
        except (OSError, ValueError, UnicodeError):
            errors.append('unreadable_or_unsupported_entry')
    incomplete = bool(errors)
    return {'schema': 'boxcop.skill-scan.v1', 'assessment': 'review_required' if records else 'incomplete' if incomplete else 'no_pattern_match',
            'incomplete': incomplete, 'entries_checked': min(count, MAX_FILES),
            'findings': records, 'errors': sorted(set(errors))}
