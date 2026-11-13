"""Portable context contract tests using synthetic evidence only."""
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import patch
import unittest
from uuid import uuid4

from server.workflow_context import WorkflowContextStore, validate_context


def fixture(count=2):
    session = str(uuid4())
    stamp = datetime.now(timezone.utc).isoformat()
    events = []
    for index in range(count):
        events.append(dict(id=str(uuid4()), sessionID=session, sequence=index + 1,
            observedAt=stamp, receivedAt=stamp, kind='agent_instruction', phase='observed',
            collector='agent.hook', provenance='reported', availability='available', relatedEventIDs=[],
            fields={'instruction': dict(value='SYNTHETIC_PRIVATE_TEXT', provenance='reported', availability='available', truncated=False)}))
    return dict(schemaVersion='boxcop.workflow-context.v1', contextID=str(uuid4()), sessionID=session,
        revision=count, generatedAt=stamp, events=events, links=[], artifacts=[], sources=[],
        omittedEvents=0, timelineDropped=0, issues=[], enforcement='context_only_not_authorization')


def engine_event(context, identifier='3f2a9c0d1b7e4a55', **values):
    """A security_events row as the app places it in the timeline."""
    values = {'layer': 'install_gate', 'outcome': 'blocked', 'title': 'Blocked install of left-pad 1.0.1 (reported as malware)',
              'reason': 'This release is reported as malware by github, but the report is not yet confirmed.',
              'subject': 'left-pad@1.0.1', 'agent': 'claude', **values}
    context['revision'] += 1
    event = dict(id='engine:' + identifier, sessionID=context['sessionID'], sequence=context['revision'],
        observedAt=context['generatedAt'], receivedAt=context['generatedAt'], kind='security_event', phase='observed',
        collector='BoxCopEngine', provenance='engine_record', availability='available', relatedEventIDs=[],
        fields={name: dict(value=value, provenance='engine_record', availability='available', truncated=False)
                for name, value in values.items() if value is not None})
    context['events'].append(event)
    return event


class FakeClassifier:
    def __init__(self): self.seen = []
    def labels(self, text):
        self.seen.append(text)
        return ['secret']


class ContextTests(unittest.TestCase):
    def test_judgment_receives_detached_full_evidence_and_clear_expires_it(self):
        context = fixture()
        first, second = context['events']
        context['links'] = [dict(sourceEventID=first['id'], targetEventID=second['id'], relation='nearby_process_context', strength='candidate')]
        context['artifacts'] = [dict(eventID=first['id'], artifactID='synthetic', mediaType='image/png',
            localPath='/never-open-this-context-reference', availability='local_reference_may_expire')]
        store, classifier = WorkflowContextStore(), FakeClassifier()
        with patch('builtins.open', side_effect=AssertionError('must not open artifact')):
            result = store.accept(context, classifier)
            self.assertEqual(store.for_judgment(), context)
        self.assertTrue(result['shadowOnly'])
        self.assertEqual(result['classifiedFields'], 2)
        self.assertNotIn('SYNTHETIC_PRIVATE_TEXT', str(result))
        context['events'].clear()
        detached = store.for_judgment(); detached['events'].clear()
        self.assertEqual(len(store.for_judgment()['events']), 2)
        with patch('server.workflow_context.monotonic', return_value=store._accepted_at + 16):
            self.assertIsNone(store.for_judgment())
        store.clear(); self.assertIsNone(store.for_judgment())

    def test_classification_budget_and_clipped_text_are_explicit(self):
        context = fixture(12)
        context['events'][-1]['fields']['instruction']['truncated'] = True
        classifier = FakeClassifier()
        result = WorkflowContextStore().accept(context, classifier)
        self.assertEqual(result['classifiedFields'], 8)
        self.assertEqual(result['omittedTextFields'], 4)
        self.assertTrue(result['incomplete'])
        self.assertEqual(len(classifier.seen), 8)

    def test_network_block_is_evidence_not_a_new_authorization(self):
        context = fixture(1)
        context['events'][0].update(collector='NetworkExtension', kind='network_connection', fields={
            'decision': dict(value='blocked_threat_domain', availability='available', provenance='observed', truncated=False)})
        result = WorkflowContextStore().accept(context, FakeClassifier())
        self.assertEqual(result['signals'], [dict(eventID=context['events'][0]['id'], kind='observed_domain_block')])
        self.assertTrue(result['shadowOnly'])
        self.assertEqual(result['classifiedFields'], 0)

    def test_invalid_context_cannot_replace_current_evidence(self):
        original = fixture()
        store = WorkflowContextStore(); store.accept(original, FakeClassifier())
        mutations = [
            lambda c: c.update(enforcement='allow'),
            lambda c: c.update(revision=True),
            lambda c: c.update(events=c['events'] * 33),
            lambda c: c['events'][0].update(sessionID=str(uuid4())),
            lambda c: c['events'][0]['fields']['instruction'].update(value='x' * 4097),
            lambda c: c.update(links=[dict(sourceEventID=str(uuid4()), targetEventID=c['events'][0]['id'], relation='fake', strength='candidate')]),
            lambda c: c.update(links=[dict(sourceEventID=[], targetEventID=c['events'][0]['id'], relation='fake', strength='candidate')]),
            lambda c: c.update(links=[dict(sourceEventID=c['events'][0]['id'], targetEventID=c['events'][1]['id'], relation='fake', strength={})]),
            lambda c: c['events'][0]['fields']['instruction'].update(truncated='false'),
            lambda c: c.update(generatedAt='2026-11-03T12:00:00'),
            lambda c: c.update(events=[c['events'][0], c['events'][0]]),
        ]
        for mutate in mutations:
            invalid = deepcopy(original); mutate(invalid)
            with self.assertRaises(ValueError): store.accept(invalid, FakeClassifier())
            self.assertEqual(store.for_judgment(), original)

    def test_engine_security_event_is_accepted_and_can_be_linked(self):
        context = fixture(1)
        record = engine_event(context, identifier='0b9c2f7e-1111-4222-8333-444455556666', agent=None, subject=None)
        first = context['events'][0]
        first['relatedEventIDs'] = [record['id']]
        context['links'] = [dict(sourceEventID=first['id'], targetEventID=record['id'], relation='preceded', strength='candidate')]
        context['artifacts'] = [dict(eventID=record['id'], artifactID='a', mediaType='text/plain', availability='available')]
        self.assertIs(validate_context(context), context)
        classifier = FakeClassifier()
        result = WorkflowContextStore().accept(context, classifier)
        self.assertEqual((result['eventCount'], result['linkCount']), (2, 1))
        # Engine text is already redacted and is not one of the classified evidence fields.
        self.assertEqual(classifier.seen, ['SYNTHETIC_PRIVATE_TEXT'])

    def test_engine_security_event_shape_is_strict(self):
        mutations = [
            lambda c, e: e.update(id=str(uuid4())),                        # A security_event needs an engine id,
            lambda c, e: e.update(kind='agent_tool_call'),                 # and an engine id needs that kind.
            lambda c, e: e.update(id='engine:'), lambda c, e: e.update(id='engine:has space'),
            lambda c, e: e.update(id='engine:' + 'a' * 65), lambda c, e: e.update(id='engine:a/b'),
            lambda c, e: e.update(collector='agent.hook'),
            lambda c, e: e['fields'].pop('layer'), lambda c, e: e['fields'].pop('outcome'), lambda c, e: e['fields'].pop('title'),
            lambda c, e: e['fields']['outcome'].update(value='held'), lambda c, e: e['fields']['outcome'].update(value='approved'),
            lambda c, e: e['fields']['layer'].update(value='Install Gate'),
            lambda c, e: e['fields']['title'].update(value=''), lambda c, e: e['fields']['title'].update(value='x' * 301),
            lambda c, e: e['fields']['reason'].update(value='x' * 601),
            lambda c, e: e['fields']['agent'].update(value=None),
            lambda c, e: e['fields'].update(command=dict(value='rm -rf', provenance='p', availability='available', truncated=False)),
            lambda c, e: c['events'].append(dict(e)),                      # The same row twice.
            lambda c, e: c.update(links=[dict(sourceEventID='engine:missing', targetEventID=e['id'], relation='r', strength='candidate')]),
        ]
        for index, mutate in enumerate(mutations):
            context = fixture(1); event = engine_event(context)
            validate_context(deepcopy(context))
            mutate(context, event)
            with self.assertRaises(ValueError, msg=index): validate_context(context)

    def test_byte_budget_checks_utf8_not_character_count(self):
        context = fixture(20)
        for event in context['events']:
            event['fields']['instruction']['value'] = '界' * 4096
        with self.assertRaises(ValueError): validate_context(context)


if __name__ == '__main__':
    unittest.main()
