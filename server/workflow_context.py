"""Ephemeral, bounded workflow evidence for local classifier/judgment consumers.

No paths are opened, captured instructions executed, or decisions authorized here.
The content classifier remains content-only; context evidence is kept separately.
"""
from copy import deepcopy
from datetime import datetime
import json
from uuid import UUID
from time import monotonic

SCHEMA = 'boxcop.workflow-context.v1'
MAX_BYTES = 96 * 1024
TEXT_FIELDS = ('instruction', 'arguments', 'result_summary', 'recognized_text', 'selected_text', 'context_text')
SENSITIVE = {'secret', 'private-key', 'ssn', 'medical', 'hr-sensitive', 'restricted-business'}


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)).lower() != value.lower():
        raise ValueError('Invalid ID')


def _text(value, limit=4096):
    if not isinstance(value, str) or len(value) > limit or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError('Invalid text')


def _date(value):
    _text(value, 64)
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.tzinfo is None:
        raise ValueError('Timestamp timezone missing')
    return date


def validate_context(context):
    required = {'schemaVersion', 'contextID', 'sessionID', 'revision', 'generatedAt', 'events', 'links',
                'artifacts', 'sources', 'omittedEvents', 'timelineDropped', 'issues', 'enforcement'}
    if not isinstance(context, dict) or set(context) != required or context['schemaVersion'] != SCHEMA:
        raise ValueError('Invalid context schema')
    if len(json.dumps(context, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()) > MAX_BYTES:
        raise ValueError('Context too large')
    for name in ('contextID', 'sessionID'):
        _uuid(context[name])
    _date(context['generatedAt'])
    for name in ('revision', 'omittedEvents', 'timelineDropped'):
        if type(context[name]) is not int or not 0 <= context[name] <= 2**53:
            raise ValueError('Invalid count')
    if context['enforcement'] != 'context_only_not_authorization':
        raise ValueError('Invalid enforcement mode')
    for name, limit in [('events', 64), ('links', 256), ('artifacts', 64), ('sources', 16), ('issues', 32)]:
        if not isinstance(context[name], list) or len(context[name]) > limit:
            raise ValueError('Invalid collection')
    for issue in context['issues']:
        _text(issue, 128)
    ids = set()
    for event in context['events']:
        required_event = {'id', 'sessionID', 'sequence', 'observedAt', 'receivedAt', 'kind', 'phase',
                          'collector', 'provenance', 'availability', 'fields', 'relatedEventIDs'}
        if not isinstance(event, dict) or not required_event <= set(event) or set(event) - required_event - {'bundleID', 'pid', 'windowTitle'}:
            raise ValueError('Invalid event')
        _uuid(event['id']); _uuid(event['sessionID'])
        if event['id'] in ids or event['sessionID'] != context['sessionID']:
            raise ValueError('Duplicate or foreign-session event')
        ids.add(event['id'])
        if type(event['sequence']) is not int or not 1 <= event['sequence'] <= context['revision']:
            raise ValueError('Invalid sequence')
        _date(event['observedAt']); _date(event['receivedAt'])
        for name in ('kind', 'phase', 'collector', 'provenance', 'availability'):
            _text(event[name], 128)
        for name in ('bundleID', 'windowTitle'):
            if event.get(name) is not None: _text(event[name], 512)
        if event.get('pid') is not None and (type(event['pid']) is not int or not 0 < event['pid'] <= 2**31 - 1):
            raise ValueError('Invalid PID')
        if not isinstance(event['fields'], dict) or len(event['fields']) > 64:
            raise ValueError('Invalid fields')
        for name, field in event['fields'].items():
            _text(name, 128)
            if not isinstance(field, dict) or not {'provenance', 'availability', 'truncated'} <= set(field) or set(field) - {'value', 'provenance', 'availability', 'truncated'}:
                raise ValueError('Invalid field')
            if field.get('value') is not None: _text(field['value'])
            _text(field['provenance'], 128); _text(field['availability'], 128)
            if type(field['truncated']) is not bool: raise ValueError('Invalid truncation flag')
        if not isinstance(event['relatedEventIDs'], list) or len(event['relatedEventIDs']) > 16:
            raise ValueError('Invalid references')
        for reference in event['relatedEventIDs']: _uuid(reference)
    for link in context['links']:
        if not isinstance(link, dict) or set(link) != {'sourceEventID', 'targetEventID', 'relation', 'strength'}:
            raise ValueError('Invalid link')
        _uuid(link['sourceEventID']); _uuid(link['targetEventID']); _text(link['strength'], 128)
        if link['sourceEventID'] not in ids or link['targetEventID'] not in ids:
            raise ValueError('Dangling link')
        if link['strength'] not in {'recorded_reference', 'shared_identifier', 'candidate'}:
            raise ValueError('Invalid strength')
        _text(link['relation'], 128)
    for artifact in context['artifacts']:
        if not isinstance(artifact, dict) or not {'eventID', 'artifactID', 'mediaType', 'availability'} <= set(artifact) or set(artifact) - {'eventID', 'artifactID', 'mediaType', 'availability', 'localPath'}:
            raise ValueError('Invalid artifact')
        _uuid(artifact['eventID'])
        if artifact['eventID'] not in ids: raise ValueError('Dangling artifact')
        for name in ('artifactID', 'mediaType', 'availability'): _text(artifact[name], 128)
        if artifact.get('localPath') is not None: _text(artifact['localPath'])
    for source in context['sources']:
        if not isinstance(source, dict) or set(source) != {'source', 'state', 'detail'}:
            raise ValueError('Invalid source state')
        for name in source: _text(source[name], 512)
    return context


class WorkflowContextStore:
    def __init__(self, judge=None):
        self.judge = judge
        self._context = None
        self._accepted_at = 0

    def clear(self):
        if self.judge is not None: self.judge.clear()
        self._context = None
        self._accepted_at = 0

    def for_judgment(self):
        """Return evidence, not instructions; references never cause filesystem reads."""
        if self._context is None or monotonic() - self._accepted_at > 15:
            return None
        return deepcopy(self._context)

    def accept(self, context, classifier):
        validate_context(context)
        self._context = deepcopy(context)
        self._accepted_at = monotonic()
        signals, classified, omitted = [], 0, 0
        for event in reversed(context['events']):
            fields = event['fields']
            decision = fields.get('decision', {}).get('value')
            if event['collector'] == 'NetworkExtension' and decision == 'blocked_threat_domain':
                signals.append({'eventID': event['id'], 'kind': 'observed_domain_block'})
            for name in TEXT_FIELDS:
                field = fields.get(name, {})
                text = field.get('value')
                if not text:
                    continue
                if classified >= 8 or field.get('truncated') or field.get('availability') != 'available':
                    omitted += 1
                    continue
                labels = classifier.labels(text)
                classified += 1
                if SENSITIVE.intersection(labels):
                    signals.append({'eventID': event['id'], 'kind': 'sensitive_content_label'})
        incomplete = bool(omitted or context['issues'] or context['omittedEvents'] or context['timelineDropped'] or
                          any(s['state'] != 'active' for s in context['sources']))
        if self.judge is not None: self.judge.submit(context)
        return {'judgment': self.judge.status() if self.judge is not None else None,
                'contextID': context['contextID'], 'eventCount': len(context['events']), 'linkCount': len(context['links']),
                'incomplete': incomplete, 'classifiedFields': classified, 'omittedTextFields': omitted,
                'signals': signals[:16], 'shadowOnly': True}
