"""One newest-first list of what BoxCop blocked, across the engine's layers.

Read-only. It reports what each layer already records: hook decisions in the
audit store, registry firewall blocks and contained-script connection blocks. Network extension events and software findings are merged
by the app from their own sources.
"""
from datetime import datetime, timezone
import json

from .event_log import EventLog
from .models import POLICIES
from .package_scripts import CONTAINMENT_LOG

AGENTS = {'claude': 'Claude Code', 'codex': 'Codex', 'cursor': 'Cursor'}
AGENT_IDS = {label: key for key, label in AGENTS.items()}
POLICY_NAMES = {policy['id']: policy['name'] for policy in POLICIES}
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
           package=None, host=None, policy_ids=(), ecosystem=None, version=None, allowable=False):
    """`outcome` is blocked or warned. `allowable` marks a block the user may lift for that exact release."""
    return {'id': identifier, 'time': when, 'layer': layer, 'outcome': outcome, 'title': title, 'reason': reason,
            'subject': subject, 'agent': agent if agent in AGENTS else None, 'command': command,
            'package': package, 'host': host, 'policy_ids': list(policy_ids),
            'ecosystem': ecosystem, 'version': version, 'allowable': allowable}


# What a denied command was about to do, most serious first.
COMMAND_TITLES = {
    'known-malicious-package': 'installing a known-malicious package',
    'credential-file-egress': 'sending a credential file',
    'command-sensitive-egress': 'sending sensitive data',
    'remote-shell': 'running a downloaded script',
    'credential-file-access': 'reading a credential file',
    'download-then-exec': 'downloading and running a file',
    'vulnerable-runtime': 'installing a vulnerable runtime',
}


def hook_events(store, limit):
    """Actions a pre-action hook denied. Include command review details when the hook recorded them."""
    events = []
    for record in store.list_events(limit=limit, decision='denied')['items']:
        event, decision = record['event'], record['decision']
        policies = decision['policy_ids']
        when = _time(record['created_at'])
        if when is None:
            continue
        skill = any(policy.startswith('skill-') for policy in policies)
        install = skill or bool(INSTALL_POLICIES.intersection(policies))
        who = AGENTS.get(event['app'], 'an agent')
        action = event['action']
        path = event['destination'] if action != 'command' else None
        if action == 'command':
            what = next((COMMAND_TITLES[policy] for policy in policies if policy in COMMAND_TITLES), None)
            title = f'Blocked {who} from {what}' if what else f'Blocked a command from {who}'
        elif skill:
            title = f'Blocked {who} from loading unsafe agent instructions'
        else:
            title = f'Blocked a file {action} by {who}'
        events.append(_event(
            record['id'], when, 'install_gate' if install else 'agent_actions', 'blocked', title,
            ' '.join(decision['reasons'])[:600],
            subject=path or ', '.join(POLICY_NAMES.get(policy, policy) for policy in policies[:2]) or None,
            agent=event['app'], policy_ids=policies))
        if action == 'command':
            review = record.get('command_review')
            if review:
                events[-1].update(review, working_directory=event['source'].partition(':')[2] or None)
            elif event['source'].startswith('reported-'):
                events[-1]['retry_note'] = 'This hook did not retain the command. Retry in the agent to record a new event.'
    return events


def firewall_events(directory, limit):
    """Package releases the registry firewall refused to serve."""
    from .package_exceptions import Exceptions
    allowed = {(row['ecosystem'], row['package'], row['version']) for row in Exceptions(directory).read()}
    events = []
    for row in EventLog(directory / FIREWALL_LOG).read()[-limit:]:
        when, name = _time(row.get('time')), row.get('package')
        if when is None or not isinstance(name, str):
            continue
        version = row.get('version') if isinstance(row.get('version'), str) else None
        ecosystem = row.get('ecosystem') if row.get('ecosystem') in ('npm', 'PyPI') else None
        sources = [source for source in row.get('sources', []) if isinstance(source, str)][:3]
        named = ' by ' + ', '.join(sources) if sources else ''
        reported = row.get('tier') == 'reported' and not row.get('self_test')
        title = 'Blocked install of ' + name + (' ' + version if version else '')
        if row.get('self_test'):
            reason = 'This is the BoxCop test package. It is always blocked so you can check that the install gate works.'
        elif reported:
            title += ' (reported as malware)'
            if version:
                reason = (f'This release is reported as malware{named}, but the report is not yet confirmed.'
                          ' If you are sure it is safe, you can allow this exact version.')
            else:
                reason = (f'Every available version of this package is reported as malware{named}, but the reports'
                          ' are not yet confirmed. To allow one, install an exact version and allow it from that event.')
        else:
            reason = f'This release is confirmed malware{named}. It cannot be allowed.'
        events.append(_event(row['id'], when, 'install_gate', 'blocked', title, reason,
                             subject=name + ('@' + version if version else ''), package=name,
                             policy_ids=['known-malicious-package'], ecosystem=ecosystem, version=version,
                             allowable=bool(reported and version and ecosystem
                                            and (ecosystem, name, version) not in allowed)))
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


def security_events(limit, *, store, package_directory, script_directory):
    events = [*hook_events(store, limit), *firewall_events(package_directory, limit),
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
