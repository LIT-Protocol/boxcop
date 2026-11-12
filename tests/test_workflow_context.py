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

    def test_byte_budget_checks_utf8_not_character_count(self):
        context = fixture(20)
        for event in context['events']:
            event['fields']['instruction']['value'] = '界' * 4096
        with self.assertRaises(ValueError): validate_context(context)


if __name__ == '__main__':
    unittest.main()
