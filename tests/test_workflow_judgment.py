"""Synthetic, offline contract and concurrency tests for advisory workflow reasoning."""
import json
import time
import unittest
from threading import Event
from unittest.mock import patch
from test_workflow_context import fixture
from server.workflow_judgment import WorkflowJudge, LocalWorkflowModel, compact, validate_result, strict_json


def response(packet, risk='needs_review'):
    return dict(intent='Review a public report', risk=risk,
        findings=[] if risk in ('no_concern_observed', 'insufficient_evidence') else [dict(
            summary='A tool request warrants review in the task context.', evidence=[packet['events'][0]['ref']],
            recommendation='Review the destination and requested data.')],
        uncertainties=['The network record does not establish payload transfer.'])


def wait_for(predicate):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.005)
    raise AssertionError('Worker did not reach expected state')


class JudgmentTests(unittest.TestCase):
    def test_compaction_preserves_modalities_and_explicit_loss(self):
        context = fixture(32)
        for e in context['events']:
            e['fields']['instruction']['value'] = '界' * 4096
        context['events'][0]['collector'] = 'ScreenCaptureKit.window'
        packet, aliases = compact(context)
        self.assertLessEqual(len(json.dumps(packet, ensure_ascii=False).encode()), 10100)
        self.assertTrue(packet['modelInputTruncated'])
        self.assertGreater(packet['omittedEvents'], 0)
        self.assertIn('ScreenCaptureKit.window', {e['collector'] for e in packet['events']})
        self.assertEqual(len(aliases), len(packet['events']))

    def test_citations_are_bound_to_the_actual_model_input(self):
        packet, aliases = compact(fixture())
        result = validate_result(response(packet), aliases)
        self.assertEqual(result['findings'][0]['eventIDs'], [aliases[packet['events'][0]['ref']]])
        invalid = response(packet); invalid['findings'][0]['evidence'] = ['invented']
        with self.assertRaises(ValueError): validate_result(invalid, aliases)
        invalid['findings'][0]['evidence'] = [[]]
        with self.assertRaises(ValueError): validate_result(invalid, aliases)
        with self.assertRaises(ValueError): strict_json('{"risk":"high_risk","risk":"no_concern_observed"}')
        invalid = response(packet, 'high_risk'); invalid['findings'] = []
        with self.assertRaises(ValueError): validate_result(invalid, aliases)

    def test_async_latest_snapshot_and_clear_discard_inflight(self):
        started, release = Event(), Event()
        def model(packet):
            started.set(); release.wait(2)
            return response(packet)
        judge = WorkflowJudge(model, interval=0)
        self.addCleanup(judge.close)
        before = time.monotonic(); judge.submit(fixture())
        self.assertLess(time.monotonic() - before, .1)
        self.assertTrue(started.wait(1)); judge.clear(); release.set()
        wait_for(lambda: judge._active is None)
        self.assertEqual(judge.status()['state'], 'waiting')
        self.assertNotIn('result', judge.status())

    def test_result_identifies_reviewed_snapshot_and_marks_new_activity(self):
        judge = WorkflowJudge(response, interval=60)
        self.addCleanup(judge.close)
        context = fixture(); judge.submit(context)
        wait_for(lambda: judge.status()['state'] == 'ready')
        first = judge.status()
        self.assertFalse(first['superseded']); self.assertTrue(first['advisoryOnly'])
        self.assertEqual(first['result']['contextID'], context['contextID'])
        self.assertEqual(first['result']['revision'], context['revision'])
        newer = fixture()
        newer['sessionID'] = context['sessionID']
        for event in newer['events']: event['sessionID'] = context['sessionID']
        judge.submit(newer)
        self.assertTrue(judge.status()['superseded'])
        self.assertIsNotNone(judge._pending)
        judge.submit(newer)
        self.assertIsInstance(judge._pending, tuple)  # one latest slot, not an accumulating queue
        judge._completed -= 121
        self.assertNotIn('result', judge.status())

    def test_errors_never_become_safe_and_shutdown_invalidates(self):
        judge = WorkflowJudge(lambda packet: {'risk': 'safe'}, interval=0)
        self.addCleanup(judge.close)
        judge.submit(fixture())
        wait_for(lambda: judge.status()['state'] == 'unavailable')
        self.assertNotIn('result', judge.status())
        judge.close(); judge.submit(fixture())
        self.assertIsNone(judge._pending)

    def test_new_session_and_empty_snapshot_invalidate_old_inflight_result(self):
        for empty in (False, True):
            started, release = Event(), Event()
            def model(packet):
                started.set(); release.wait(2)
                return response(packet)
            judge = WorkflowJudge(model, interval=0)
            self.addCleanup(judge.close)
            old = fixture(); judge.submit(old)
            self.assertTrue(started.wait(1))
            newer = fixture(0 if empty else 2)
            judge.submit(newer); release.set()
            if empty:
                wait_for(lambda: judge._active is None)
                self.assertEqual(judge.status()['state'], 'insufficient_evidence')
                self.assertNotIn('result', judge.status())
            else:
                wait_for(lambda: judge.status()['state'] == 'ready')
                self.assertEqual(judge.status()['result']['contextID'], newer['contextID'])

    def test_empty_context_never_calls_model(self):
        def model(packet): raise AssertionError('No evidence')
        judge = WorkflowJudge(model)
        self.addCleanup(judge.close)
        judge.submit(fixture(0))
        self.assertEqual(judge.status()['state'], 'insufficient_evidence')
        self.assertIsNone(judge._worker)

    def test_slow_model_setup_reviews_latest_pending_snapshot(self):
        started, release = Event(), Event()
        seen = []
        class Model:
            def prepare(self): started.set(); release.wait(2)
            def __call__(self, packet): seen.append(packet); return response(packet)
        judge = WorkflowJudge(Model(), interval=0)
        self.addCleanup(judge.close)
        first = fixture(); judge.submit(first); self.assertTrue(started.wait(1))
        latest = fixture(); latest['sessionID'] = first['sessionID']
        latest['events'][0]['fields']['instruction']['value'] = 'Newest task'
        judge.submit(latest); release.set()
        wait_for(lambda: judge.status()['state'] == 'ready')
        self.assertEqual(len(seen), 1)
        self.assertEqual(judge.status()['result']['contextID'], latest['contextID'])
        self.assertIn('Newest task', json.dumps(seen[0]))

    def test_model_uses_owned_runtime_with_bound_schema_and_no_tools(self):
        packet, _ = compact(fixture())
        class Runtime:
            def chat(self, messages, schema):
                self.messages, self.schema = messages, schema
                return json.dumps(response(packet))
        runtime = Runtime()
        self.assertEqual(LocalWorkflowModel(runtime)(packet), response(packet))
        self.assertEqual(runtime.messages[0]['role'], 'system')
        self.assertIn('untrusted DATA', runtime.messages[0]['content'])
        self.assertEqual(json.loads(runtime.messages[1]['content']), packet)
        self.assertEqual(runtime.schema['properties']['findings']['items']['properties']['evidence']['items']['enum'],
                         [e['ref'] for e in packet['events']])



class WorkflowUsageTests(unittest.TestCase):
    def test_validated_results_persist_and_coalesced_context_is_not_an_attempt(self):
        import tempfile
        from pathlib import Path
        from server.store import Store
        from server.classifier_usage import ClassifierUsage, QWEN_BACKEND, MINILM_BACKEND
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'events.sqlite3')
            usage = ClassifierUsage(store)
            judge = WorkflowJudge(response, interval=0, usage=usage)
            self.addCleanup(judge.close)
            context = fixture(); judge.submit(context)
            wait_for(lambda: judge.status()['state'] == 'ready')
            judge.submit(context)
            snapshot = judge.status()['modelUsage']
            self.assertEqual(snapshot['backends'][QWEN_BACKEND]['attempts'], 1)
            self.assertEqual(snapshot['backends'][QWEN_BACKEND]['ready'], 1)
            self.assertEqual(snapshot['backends'][MINILM_BACKEND]['attempts'], 0)
            judge.clear()
            self.assertEqual(judge.status()['modelUsage'], snapshot)
            self.assertEqual(ClassifierUsage(Store(store.path)).snapshot(), snapshot)
            for path in Path(directory).iterdir():
                self.assertNotIn(b'SYNTHETIC_PRIVATE_TEXT', path.read_bytes())
                self.assertNotIn(b'A tool request warrants review', path.read_bytes())

    def test_setup_failure_is_not_inference_and_inference_outcomes_are_attributed(self):
        from server.classifier_usage import QWEN_BACKEND
        class SetupFailure:
            def prepare(self): raise OSError('PRIVATE_SETUP')
            def __call__(self, packet): raise AssertionError('Must not infer')
        def unavailable(packet): raise TimeoutError('PRIVATE_TRANSPORT')
        for model, outcome, attempts in [(SetupFailure(), None, 0), (unavailable, 'unavailable', 1),
                (lambda packet: {'risk': 'safe'}, 'error', 1),
                (lambda packet: response(packet, 'insufficient_evidence'), 'uncertain', 1)]:
            judge = WorkflowJudge(model, interval=0)
            self.addCleanup(judge.close)
            judge.submit(fixture())
            wait_for(lambda: judge.status()['state'] in ('ready', 'unavailable'))
            status = judge.status(); counts = status['modelUsage']['backends'][QWEN_BACKEND]
            self.assertEqual(counts['attempts'], attempts)
            if outcome: self.assertEqual(counts[outcome], 1)
            self.assertNotIn('PRIVATE_', json.dumps(status))

    def test_inflight_work_counts_after_clear_but_cannot_restore_judgment(self):
        from server.classifier_usage import QWEN_BACKEND
        entered, release = Event(), Event()
        def model(packet):
            entered.set(); release.wait(2)
            return response(packet)
        judge = WorkflowJudge(model, interval=0)
        self.addCleanup(judge.close)
        judge.submit(fixture()); self.assertTrue(entered.wait(1))
        judge.clear(); release.set()
        wait_for(lambda: judge._active is None)
        self.assertNotIn('result', judge.status())
        counts = judge.status()['modelUsage']['backends'][QWEN_BACKEND]
        self.assertEqual((counts['attempts'], counts['ready']), (1, 1))


if __name__ == '__main__': unittest.main()
