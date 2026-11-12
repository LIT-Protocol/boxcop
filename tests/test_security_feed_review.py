"""Offline feed-contract and publication boundary regressions."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('feed_review', Path(__file__).resolve().parents[1] / 'scripts/security_feed_review.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


def pwn(**changes):
    row = dict(id='https://pwn.watch/i/example', title='Example', content_html='<p>Issue</p>', date_modified='2026-11-03')
    row.update(changes)
    return json.dumps(dict(items=[row])).encode()


class LauncherTests(unittest.TestCase):
    def test_dependency_setup_and_argument_forwarding(self):
        launcher = Path(__file__).resolve().parents[1] / 'update_from_feed.sh'
        for mode in ['new', 'existing', 'fetch-only', 'help', 'install-failure']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='feed review ') as d:
                root = Path(d)
                (root / 'update_from_feed.sh').write_text(launcher.read_text())
                bin_dir = root / 'bin'
                bin_dir.mkdir()
                fake = bin_dir / 'python3'
                fake.write_text(f'''#!{sys.executable}
import json, os, pathlib, shutil, sys
with open(os.environ['LAUNCHER_LOG'], 'a') as log:
    log.write(json.dumps([sys.argv[0], *sys.argv[1:]]) + '\\n')
if sys.argv[1:3] == ['-m', 'venv']:
    target = pathlib.Path(sys.argv[3]) / 'bin/python'
    target.parent.mkdir(parents=True)
    shutil.copy2(__file__, target)
if sys.argv[1:3] == ['-m', 'pip'] and os.environ['LAUNCHER_MODE'] == 'install-failure':
    sys.exit(7)
''')
                fake.chmod(0o755)
                if mode == 'existing':
                    target = root / '.venv/bin/python'
                    target.parent.mkdir(parents=True)
                    target.write_text(fake.read_text())
                    target.chmod(0o755)
                log = root / 'calls.jsonl'
                args = ['--fetch-only'] if mode == 'fetch-only' else ['--help'] if mode == 'help' else ['--no-publish']
                result = subprocess.run(
                    ['/bin/bash', str(root / 'update_from_feed.sh'), *args], cwd='/',
                    env={**os.environ, 'PATH': f'{bin_dir}:/usr/bin:/bin',
                         'LAUNCHER_LOG': str(log), 'LAUNCHER_MODE': mode},
                    capture_output=True, text=True)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                setup = mode not in ['fetch-only', 'help']
                self.assertEqual(result.returncode, 7 if mode == 'install-failure' else 0)
                self.assertEqual(any(c[1:3] == ['-m', 'venv'] for c in calls), setup and mode != 'existing')
                pip_calls = [c for c in calls if c[1:3] == ['-m', 'pip']]
                self.assertEqual(len(pip_calls), int(setup))
                if setup:
                    self.assertEqual(pip_calls[0], [str(root / '.venv/bin/python'), '-m', 'pip', 'install', '-r', str(root / 'requirements.txt')])
                if mode != 'install-failure':
                    self.assertEqual(calls[-1][1:], [str(root / 'scripts/security_feed_review.py'), *args])
                else:
                    self.assertEqual(calls[-1][1:3], ['-m', 'pip'])


class FeedTests(unittest.TestCase):
    def test_missing_pytest_explains_setup_and_stops_before_review(self):
        with tempfile.TemporaryDirectory() as d, patch.object(review, 'ROOT', Path(d)), \
                patch.object(review, 'collect', return_value=[]), \
                patch.object(sys, 'argv', ['review']), patch.object(review, 'run') as run:
            run.side_effect = subprocess.CalledProcessError(
                1, 'python', stderr="ModuleNotFoundError: No module named 'pytest'")
            with self.assertRaises(RuntimeError) as raised:
                review.main()
            message = str(raised.exception)
            self.assertIn(sys.executable, message)
            self.assertIn('python3 -m venv .venv', message)
            self.assertIn('.venv/bin/python -m pip install -r requirements.txt', message)
            self.assertIn("No module named 'pytest'", message)
            run.assert_called_once_with([sys.executable, '-c', 'import pytest'], stderr=subprocess.PIPE)

    def test_fetch_only_skips_test_dependencies(self):
        with tempfile.TemporaryDirectory() as d, patch.object(review, 'ROOT', Path(d)), \
                patch.object(review, 'collect', return_value=[]), \
                patch.object(sys, 'argv', ['review', '--fetch-only']), patch.object(review, 'run') as run:
            review.main()
            run.assert_not_called()

    def test_live_format_rss_uses_stable_link_not_dated_guid(self):
        xml = b'''<rss><channel><item><title>Example</title><link>https://radar.cloudflare.com/security/zero-wire/example</link><guid>example@2026-11-01</guid><description>Issue</description></item></channel></rss>'''
        a = review.parse_feed('zero-wire', xml)[0]
        b = review.parse_feed('zero-wire', xml.replace(b'@2026-11-01', b'@2026-11-02'))[0]
        self.assertEqual(a, b)

    def test_content_changes_detected_even_without_timestamp_change(self):
        a = review.parse_feed('pwn', pwn())[0]
        b = review.parse_feed('pwn', pwn(content_html='<p>New fixed release</p>'))[0]
        self.assertEqual(a['id'], b['id'])
        self.assertNotEqual(a['fingerprint'], b['fingerprint'])

    def test_html_is_data_with_source_links(self):
        row = review.parse_feed('pwn', pwn(content_html='<script>evil()</script><p>Patch <a href="https://vendor.example/fix">here</a></p>'))[0]
        self.assertEqual(row['text'], 'Patch here')
        self.assertEqual(row['links'], ['https://vendor.example/fix'])

    def test_reject_challenges_empty_duplicates_entities_bad_types(self):
        for source, data in [('zero-wire', b'<html>Just a moment</html>'),
                             ('zero-wire', b'<!DOCTYPE rss><rss><channel/></rss>'),
                             ('pwn', b'{"items":[]}'), ('pwn', b'{"items":[42]}'), ('pwn', pwn(title=None)),
                             ('pwn', pwn(id='file:///tmp/x'))]:
            with self.subTest(source=source, data=data):
                with self.assertRaises(ValueError):
                    review.parse_feed(source, data)
        data = json.loads(pwn())
        data['items'] *= 2
        with self.assertRaises(ValueError):
            review.parse_feed('pwn', json.dumps(data).encode())

    def test_fetch_failure_does_not_review_or_publish(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(review, 'ROOT', Path(directory)), \
                patch.object(sys, 'argv', ['review']), patch.object(review, 'run') as run:
            run.side_effect = subprocess.CalledProcessError(22, 'curl')
            with self.assertRaises(subprocess.CalledProcessError):
                review.main()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0], 'curl')

    def test_ledger_requires_all_items_current_fingerprints_and_evidence(self):
        items = review.parse_feed('pwn', pwn())
        row = dict(id=items[0]['id'], fingerprint=items[0]['fingerprint'], status='gap',
                   rationale='No current detector exists; implement a reviewed version check.', evidence=[])
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / 'ledger.json'
            def check(rows):
                path.write_text(json.dumps(dict(schema='boxcop.security-feed-review.v1', items=rows)))
                return review.validate_review(path, items, root)
            check([row])
            with self.assertRaises(ValueError):
                review.validate_review(path, items, root, ['historical-incident'])
            for rows in [[], [row, row], [dict(row, fingerprint='old')], [dict(row, status='covered')],
                         [dict(row, status='partial', evidence=['missing.py'])]]:
                with self.assertRaises(ValueError):
                    check(rows)
            (root / 'tests').mkdir()
            (root / 'tests/check.py').write_text('')
            check([dict(row, status='covered', evidence=['tests/check.py'])])
            with self.assertRaises(ValueError):
                check([dict(row, evidence=['../outside.py'])])

    def test_changed_scope_rejects_workflow_changes(self):
        with patch.object(review, 'output', side_effect=['server/rule.py', '.github/workflows/run.yml']):
            with self.assertRaises(ValueError):
                review.changed_paths(Path('.'))

    def test_pipeline_gates_publication_and_supports_no_publish(self):
        # Exercise orchestration without a model, credentials, network or real push.
        for mode in ['publish', 'no-publish', 'test-failure', 'open-pr']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                calls = []
                def fake_run(args, cwd=None, **kwargs):
                    calls.append([str(x) for x in args])
                    if args[:3] == ['git', 'worktree', 'add']:
                        Path(args[-2]).mkdir(parents=True)
                        for test in review.TESTS:
                            target = Path(args[-2]) / test
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.touch()
                    if args[0] == 'codex' and 'exec' in args:
                        local = Path(cwd) / '.context/security-feed-review'
                        (local / 'pr-body.md').write_text('Verified coverage additions with source links and affected/fixed boundary tests. Remaining gaps are recorded.')
                    if '-m' in args and 'pytest' in args and mode == 'test-failure':
                        raise subprocess.CalledProcessError(1, args)
                    return subprocess.CompletedProcess(args, 0)
                def fake_output(args, cwd=None):
                    if args[:3] == ['gh', 'pr', 'list']:
                        return json.dumps([dict(headRefName=review.PREFIX+'existing', url='https://example.com/pr')]) if mode == 'open-pr' else '[]'
                    if args[:2] == ['git', 'rev-parse']:
                        return 'base'
                    if args[:2] == ['git', 'branch']:
                        return next(c[4] for c in calls if c[:3] == ['git', 'worktree', 'add'])
                    return ''
                argv = ['review'] + (['--no-publish'] if mode == 'no-publish' else [])
                with patch.object(review, 'ROOT', root), patch.object(review, 'collect', return_value=[]), \
                        patch.object(review, 'run', side_effect=fake_run), patch.object(review, 'output', side_effect=fake_output), \
                        patch.object(review, 'validate_review'), patch.object(review, 'changed_paths', return_value=['server/rule.py']), \
                        patch.object(sys, 'argv', argv):
                    if mode == 'test-failure':
                        with self.assertRaises(subprocess.CalledProcessError):
                            review.main()
                    else:
                        review.main()
                pushed = any(c[:2] == ['git', 'push'] for c in calls)
                published = any(c[:3] == ['gh', 'pr', 'create'] for c in calls)
                self.assertEqual(pushed, mode == 'publish')
                self.assertEqual(published, mode == 'publish')


if __name__ == '__main__':
    unittest.main()
