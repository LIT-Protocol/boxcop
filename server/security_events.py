"""One newest-first list of what BoxCop blocked or held, across the engine's layers.

Read-only. It reports what each layer already records: hook decisions in the
audit store, approval requests, registry firewall blocks and contained-script
connection blocks. Network extension events and software findings are merged
by the app from their own sources.
"""
from datetime import datetime, timezone
import json
import time

from .classify import redact, sanitize_metadata
from .event_log import EventLog
from .models import POLICIES, REVIEW_POLICIES
from .package_scripts import CONTAINMENT_LOG

AGENTS = {'claude': 'Claude Code', 'codex': 'Codex', 'cursor': 'Cursor'}
AGENT_IDS = {label: key for key, label in AGENTS.items()}
POLICY_NAMES = {policy['id']: policy['name'] for policy in (*POLICIES, *REVIEW_POLICIES)}
# Checks on what an agent is about to install or load belong to the install gate.
INSTALL_POLICIES = frozenset({'known-malicious-package', 'vulnerable-runtime', 'unsupported-runtime',
                              'unresolved-runtime-version'})
FIREWALL_LOG = 'blocks.json'
MAX_BYTES = 200 * 1024  # The pipe frame limit is 256 KiB.


def _time(value):
    """Normalize a stored ISO timestamp or epoch seconds to UTC, or None."""
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            date = datetime.fromtimestamp(value, timezone.utc)
        else:
            date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            if date.tzinfo is None:
                return None
        return date.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (ValueError, OverflowError, OSError):
        return None


def _event(identifier, when, layer, outcome, title, reason, *, subject=None, agent=None, command=None,
           package=None, host=None, policy_ids=()):
    return {'id': identifier, 'time': when, 'layer': layer, 'outcome': outcome, 'title': title, 'reason': reason,
            'subject': subject, 'agent': agent if agent in AGENTS else None, 'command': command,
            'package': package, 'host': host, 'policy_ids': list(policy_ids)}


def _command(text):
    """A short display form of a command that was already stored for review."""
    summary = redact(sanitize_metadata(text, truncate=False))
    return summary[:300] + ('…' if len(summary) > 300 else '')


def hook_events(store, limit):
    """Actions a pre-action hook denied. The audit store keeps no command text."""
    events = []
    for record in store.list_events(limit=limit, decision='held')['items']:
        event, decision = record['event'], record['decision']
        policies = decision['policy_ids']
        when = _time(record['created_at'])
        if 'human-review-required' in policies or when is None:
            continue  # Approval requests are reported from the inbox, once each.
        skill = any(policy.startswith('skill-') for policy in policies)
        install = skill or bool(INSTALL_POLICIES.intersection(policies))
        who = AGENTS.get(event['app'], 'an agent')
        action = event['action']
        path = event['destination'] if action != 'command' else None
        if action == 'command':
            title = f'Blocked a command from {who}'
        elif skill:
            title = f'Blocked {who} from loading unsafe agent instructions'
        else:
            title = f'Blocked a file {action} by {who}'
        events.append(_event(
            record['id'], when, 'install_gate' if install else 'agent_actions', 'blocked', title,
            ' '.join(decision['reasons'])[:600],
            subject=path or ', '.join(POLICY_NAMES.get(policy, policy) for policy in policies[:2]) or None,
            agent=event['app'], policy_ids=policies))
    return events


def review_events(directory, limit):
    """Approval inbox requests: waiting, approved, rejected or expired."""
    from .host_agents import read_object
    try:
        rows = read_object(directory / 'human-review' / 'state.json')[0]['requests']
    except (OSError, ValueError, KeyError, TypeError):
        return []
    events = []
    for row in rows[-limit:] if isinstance(rows, list) else []:
        try:
            status = row['status']
            if status in ('pending', 'approved') and row['expires'] <= time.time():
                status = 'expired'  # The inbox marks this on its next write; report it now.
            outcome = {'pending': 'held', 'expired': 'held', 'approved': 'approved', 'consumed': 'approved',
                       'rejected': 'rejected'}[status]
            when = _time(row.get('reviewed_at') or row['created'])
            who = AGENTS.get(row['application'], 'agent')
            title = {'pending': f'Holding a {who} action for your approval',
                     'expired': f'A {who} approval request expired without a decision',
                     'approved': f'You approved a {who} action', 'consumed': f'You approved a {who} action',
                     'rejected': f'You rejected a {who} action'}[status]
            command = _command(row['command'])
            if when is None:
                continue
            events.append(_event(row['id'], when, 'agent_actions', outcome, title,
                                 '. '.join(str(reason) for reason in row['reasons'])[:600] + '.',
                                 subject=command[:120], agent=row['application'], command=command,
                                 policy_ids=['human-review-required']))
        except (KeyError, TypeError, AttributeError):
            continue
    return events


def firewall_events(directory, limit):
    """Package releases the registry firewall refused to serve."""
    events = []
    for row in EventLog(directory / FIREWALL_LOG).read()[-limit:]:
        when, name = _time(row.get('time')), row.get('package')
        if when is None or not isinstance(name, str):
            continue
        version = row.get('version') if isinstance(row.get('version'), str) else None
        sources = [source for source in row.get('sources', []) if isinstance(source, str)][:3]
        reason = ('This is the BoxCop test package. It is always blocked so you can check that the install gate works.'
                  if row.get('self_test') else
                  'This release is listed as malicious' + (' by ' + ', '.join(sources) if sources else '') + '.')
        events.append(_event(row['id'], when, 'install_gate', 'blocked',
                             'Blocked install of ' + name + (' ' + version if version else ''), reason,
                             subject=name + ('@' + version if version else ''), package=name,
                             policy_ids=['known-malicious-package']))
    return events


def containment_events(rows, limit):
    """Connections refused for contained install scripts and contained runs."""
    events = []
    for row in list(rows)[-limit:]:
        when, host = _time(row.get('time')), row.get('host')
        if when is None or not isinstance(row.get('id'), str):
            continue
        events.append(_event(row['id'], when, 'containment', 'blocked',
                             'Blocked a connection to ' + (host or 'an unnamed destination'),
                             str(row.get('message') or 'A contained program tried to reach a destination that is not approved.')[:600],
                             subject=host or None, agent=AGENT_IDS.get(row.get('agent')), package=row.get('package'),
                             host=host or None,
                             policy_ids=['contained-run-network' if row.get('kind') == 'run' else 'install-script-network']))
    return events


def security_events(limit, *, store, data_directory, package_directory, script_directory):
    events = [*hook_events(store, limit), *review_events(data_directory, limit),
              *firewall_events(package_directory, limit),
              *containment_events(EventLog(script_directory / CONTAINMENT_LOG).read(), limit)]
    events.sort(key=lambda event: event['time'], reverse=True)
    # Keep the newest events that fit one response frame with room to spare.
    kept, size = [], 0
    for event in events[:limit]:
        size += len(json.dumps(event, ensure_ascii=True)) + 1
        if size > MAX_BYTES:
            break
        kept.append(event)
    return kept
