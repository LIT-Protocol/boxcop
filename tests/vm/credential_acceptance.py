#!/usr/bin/env python3
"""Run inside the synthetic, SIP-enabled macOS VM. No real credentials are read.

Uses the unmodified, Developer ID signed Cursor executable in Electron's Node
mode to exercise real ES identity and descendants without an AI service.
Run with the lab's Python runtime. Enable/disable protection in BoxCop first.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid


def command(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


def status(request='credential-protection-status'):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(15)
        connection.connect('/var/run/local.boxcop.network.sock')
        connection.sendall((request + '\n').encode())
        result = b''
        while not result.endswith(b'\n'):
            chunk = connection.recv(65536)
            if not chunk:
                break
            result += chunk
        return json.loads(result) if result else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', choices=['deny', 'allow'], default='deny')
    parser.add_argument('--state', help='Expected live state; defaults to active/off for deny/allow')
    parser.add_argument('--cursor', default=str(Path.home() / 'Applications/Cursor-P01.app/Contents/MacOS/Cursor'))
    args = parser.parse_args()
    assert command(['sysctl', '-n', 'hw.model']).stdout.startswith('VirtualMac'), 'VM required'
    assert 'enabled' in command(['csrutil', 'status']).stdout, 'SIP required'
    signature = command(['codesign', '-dv', args.cursor]).stderr
    assert 'TeamIdentifier=VDXQ22DGB9' in signature and 'Identifier=com.todesktop.230313mzl4w4u92\n' in signature
    assert command(['codesign', '--verify', '--strict', args.cursor]).returncode == 0
    before = status()
    assert before and before['state'] == (args.state or ('active' if args.expected == 'deny' else 'off')), before
    results = []
    created = []
    def record(name, passed, **details):
        results.append(dict(check=name, status='PASS' if passed else 'FAIL', **details))
    def fixture(relative):
        path = Path.home() / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open('x') as file:
                file.write('BOXCOP SYNTHETIC CREDENTIAL FIXTURE\n')
        except FileExistsError:
            results.append(dict(check='fixture ' + relative, status='SKIP', reason='Existing file left untouched'))
            return None
        created.append(path)
        return str(path)
    try:
        with tempfile.TemporaryDirectory(prefix='boxcop-es-') as work:
            paths = [fixture(p) for p in ['.ssh/id_ecdsa_sk', '.ssh/id_ed25519_sk', '.aws/credentials', '.config/gcloud/application_default_credentials.json', '.netrc', '.pypirc']]
            cache = fixture('.aws/sso/cache/boxcop-test-' + uuid.uuid4().hex + '.json')
            paths = [p for p in paths if p] + [cache]
            public = fixture('.ssh/boxcop-test-' + uuid.uuid4().hex + '.pub')
            ordinary = Path(work) / 'ordinary.txt'
            ordinary.write_text('ordinary fixture')
            hard = Path(work) / 'hard-link'
            sym = Path(work) / 'symbolic-link'
            os.link(cache, hard); os.symlink(cache, sym)
            status()  # refresh metadata index before alias checks
            operations = [{'name': 'credential ' + str(Path(p).relative_to(Path.home())), 'path': p, 'mode': 'direct', 'deny': True} for i, p in enumerate(paths)]
            operations += [dict(name='hard-link', path=str(hard), mode='direct', deny=True), dict(name='symlink', path=str(sym), mode='direct', deny=True)]
            case_alias = cache.replace('/.aws/sso/cache/', '/.AWS/SSO/CACHE/')
            if os.path.exists(case_alias): operations.append(dict(name='case alias', path=case_alias, mode='direct', deny=True))
            operations += [dict(name='public key', path=public, mode='direct', deny=False), dict(name='ordinary file', path=str(ordinary), mode='direct', deny=False)]
            for mode in ['shell', 'python', 'grandchild']:
                operations.append(dict(name=mode + ' child', path=cache, mode=mode, deny=True))
            script = Path(work) / 'probe.cjs'
            script.write_text(r'''
const fs = require('fs'), cp = require('child_process');
const ops = JSON.parse(process.argv[2]); const output = [];
for (const op of ops) {
 let denied = false, error = null;
 try {
  if (op.mode === 'direct') fs.readFileSync(op.path);
  else {
   let executable, args;
   if (op.mode === 'python') { executable = process.env.BOXCOP_TEST_PYTHON; args = ['-c', 'import sys; open(sys.argv[1], "rb").read()', op.path]; }
   else if (op.mode === 'grandchild') { executable = '/bin/sh'; args = ['-c', '/bin/sh -c \'exec /bin/cat "$1"\' _ "$1"', '_', op.path]; }
   else { executable = '/bin/cat'; args = [op.path]; }
   const result = cp.spawnSync(executable, args, {encoding:'utf8'});
   denied = result.status !== 0 && /Operation not permitted|Permission denied/.test(result.stderr || '');
   if (result.error || result.status !== 0 && !denied) error = 'unexpected child failure';
  }
 } catch (e) { denied = ['EPERM','EACCES'].includes(e.code); if (!denied) error = e.code; }
 output.push({name:op.name,denied,error});
}
const times=[]; let blocked=0;
for(let i=0;i<200;i++){ const start=process.hrtime.bigint(); try {fs.readFileSync(ops[0].path);} catch(e){if(['EPERM','EACCES'].includes(e.code))blocked++;} times.push(Number(process.hrtime.bigint()-start)/1e6); }
let churnBlocked=0;
for(let i=0;i<50;i++) { const child=cp.spawnSync('/bin/cat',[ops[0].path],{encoding:'utf8'}); if(child.status!==0 && /Operation not permitted|Permission denied/.test(child.stderr||'')) churnBlocked++; }
console.log(JSON.stringify({output,times,blocked,churnBlocked}));
''')
            env = dict(os.environ, ELECTRON_RUN_AS_NODE='1', BOXCOP_TEST_PYTHON=sys.executable)
            probe = subprocess.run([args.cursor, str(script), json.dumps(operations)], env=env, capture_output=True, text=True, timeout=60)
            assert probe.returncode == 0, probe.stderr[-1000:]
            observed = json.loads(probe.stdout)
            for op, actual in zip(operations, observed['output']):
                expected = op['deny'] and args.expected == 'deny'
                record(op['name'], actual['error'] is None and actual['denied'] == expected, denied=actual['denied'], error=actual['error'])
            record('200 repeated reads', observed['blocked'] == (200 if args.expected == 'deny' else 0), blocked=observed['blocked'], median_ms=statistics.median(observed['times']), p95_ms=sorted(observed['times'])[189])
            record('50 short-lived descendants', observed['churnBlocked'] == (50 if args.expected == 'deny' else 0), blocked=observed['churnBlocked'])
            record('unscoped Python can read synthetic credential', Path(cache).read_text() == 'BOXCOP SYNTHETIC CREDENTIAL FIXTURE\n')
            record('unsigned socket client cannot disable protection', status('credential-protection-off') is None)
            record('unsigned socket client cannot grant exceptions', status('credential-allow ' + str(uuid.uuid4())) is None)
            after = status()
            record('health remains correct', after['state'] == before['state'] and after['responseFailures'] == before['responseFailures'] and after['unresolved'] == before['unresolved'])
            record('network service still responds', status('network-activity')['mode'] == 'observe_all')
            report = dict(schema='boxcop.credential-vm-acceptance.v1', expected=args.expected, macOS=command(['sw_vers','-productVersion']).stdout.strip(), sip=True, signedAgent='Cursor', before={k:v for k,v in before.items() if k!='events'}, after={k:v for k,v in after.items() if k!='events'}, results=results)
            print(json.dumps(report, indent=2))
            return int(any(r['status'] == 'FAIL' for r in results))
    finally:
        for path in reversed(created): path.unlink(missing_ok=True)

if __name__ == '__main__':
    sys.exit(main())
