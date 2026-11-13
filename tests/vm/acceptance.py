#!/usr/bin/env python3
"""Install a signed BoxCop build in the lab VM and run the acceptance checks there.

Runs on the host. Uses the existing lab access in ~/.sentinel-lab (SSH alias
`sentinel-lab`, its key and known_hosts). Sends no input to the host. The guest
password is read from ~/.sentinel-lab/credentials.json only when --sudo is given, is
passed on stdin, and is never printed or written anywhere.

  python3 tests/vm/acceptance.py install --app /path/to/BoxCop.app
  python3 tests/vm/acceptance.py run --sudo --output report.json

Turning protections on is done in the app itself (see docs/vm-lab.md).
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

LAB = Path.home() / '.sentinel-lab'
GUEST_WORK = 'SentinelLab/boxcop-acceptance'
GUEST_PY = 'SentinelLab/python-runtime/cpython-3.12.13-macos-aarch64-none/bin/python3.12'
NODE = 'v22.21.1'


def resolve_host(args):
    """The lab helper finds the acceptance VM by its MAC address; --host overrides it."""
    if not args.host and (LAB / 'lab').exists():
        found = subprocess.run([str(LAB / 'lab'), 'ip'], capture_output=True, text=True)
        if found.returncode:
            sys.exit(found.stderr.strip() or found.stdout.strip() or 'the lab VM is not reachable')
        args.host = found.stdout.strip()


def ssh(args, command, stdin=None, timeout=900, check=True):
    cmd = ['ssh', '-F', str(LAB / 'ssh_config')]
    if args.host:
        cmd.append(f'-oHostName={args.host}')
    cmd += ['sentinel-lab', command]
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        sys.exit(f'guest command failed ({p.returncode}): {command}\n{p.stdout[-1500:]}\n{p.stderr[-1500:]}')
    return p


def preflight(args):
    facts = ssh(args, 'sysctl -n hw.model; csrutil status; stat -f %Su /dev/console; whoami; sw_vers -productVersion').stdout.splitlines()
    model, sip, console, user, version = facts[:5]
    if not model.startswith('VirtualMac'):
        sys.exit(f'refusing to run: {model} is not a virtual Mac')
    if 'enabled' not in sip:
        sys.exit('refusing to run: SIP is not enabled in the guest (acceptance needs a stock security posture)')
    if console != user:
        sys.exit(f'guest GUI user is {console}, SSH user is {user}; log the SSH user into the guest desktop first')
    print(f'guest: {model}, macOS {version}, SIP enabled, GUI user {user}')


def install(args):
    app = Path(args.app).resolve()
    if not (app / 'Contents/MacOS/BoxCop').is_file():
        sys.exit(f'{app} is not a BoxCop.app')
    preflight(args)
    ssh(args, f'''set -e
mkdir -p ~/{GUEST_WORK}
pkill -x BoxCop || true; pkill -x Sentinel || true; sleep 1
rm -rf /Applications/BoxCop.app''')
    print('copying BoxCop.app to the guest')
    tar = subprocess.Popen(['tar', '-C', str(app.parent), '-cf', '-', app.name], stdout=subprocess.PIPE)
    cmd = ['ssh', '-F', str(LAB / 'ssh_config')] + ([f'-oHostName={args.host}'] if args.host else []) + ['sentinel-lab', 'tar -C /Applications -xf -']
    if subprocess.run(cmd, stdin=tar.stdout).returncode or tar.wait():
        sys.exit('copy failed')
    checks = ssh(args, '''codesign --verify --deep --strict /Applications/BoxCop.app && echo SIGNATURE_OK
spctl -a -t exec -vv /Applications/BoxCop.app 2>&1
/Applications/BoxCop.app/Contents/MacOS/BoxCop --release-profile
/Applications/BoxCop.app/Contents/Resources/engine/boxcop-engine --self-test''', check=False)
    print(checks.stdout.strip())
    if 'SIGNATURE_OK' not in checks.stdout or 'accepted' not in checks.stdout or '"ok": true' not in checks.stdout:
        sys.exit('the installed bundle failed its signature, Gatekeeper or engine self-test check')
    arch = f'node-{NODE}-darwin-arm64'
    ssh(args, f'''set -e; cd ~/{GUEST_WORK}
if [ ! -x node/bin/npm ]; then
  curl -fsSL -o node.tgz https://nodejs.org/dist/{NODE}/{arch}.tar.gz && tar -xzf node.tgz && rm -rf node && mv {arch} node && rm node.tgz
fi
node/bin/node --version''', timeout=600)
    print('installed. Open BoxCop in the guest and turn protection on, then use the run command.')


def run(args):
    preflight(args)
    script = Path(__file__).with_name('guest_acceptance.py').read_text()
    ssh(args, f'mkdir -p ~/{GUEST_WORK} && cat > ~/{GUEST_WORK}/guest_acceptance.py', stdin=script)
    flags = f'--layers {args.layers}'
    if args.listed_npm:
        flags += f' --listed-npm {args.listed_npm}'
    if args.reported_npm:
        flags += f' --reported-npm {args.reported_npm}'
    if args.live_claude:
        flags += ' --live-claude'
    stdin = None
    if args.sudo:
        flags += ' --sudo-stdin'
        stdin = json.loads((LAB / 'credentials.json').read_text())['password'] + '\n'
    p = ssh(args, f'~/{GUEST_PY} ~/{GUEST_WORK}/guest_acceptance.py {flags}', stdin=stdin, timeout=1800, check=False)
    try:
        report = json.loads(p.stdout)
    except ValueError:
        sys.exit(f'no report from the guest:\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}')
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=1) + '\n')
    for r in report['results']:
        print(f"{r['status']:4}  {r['layer']:17} {r['check']}")
    print(report['summary'])
    return 1 if report['summary']['FAIL'] else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('install', 'run'):
        s = sub.add_parser(name)
        s.add_argument('--host', help='guest IP; by default ~/.sentinel-lab/lab finds it')
    sub.choices['install'].add_argument('--app', required=True)
    r = sub.choices['run']
    r.add_argument('--output')
    r.add_argument('--layers', default='1,2,3,4,5')
    r.add_argument('--listed-npm', default='', help='a published name@version the feed marks confirmed malware')
    r.add_argument('--reported-npm', default='', help='a published name@version the feed marks reported, not confirmed')
    r.add_argument('--live-claude', action='store_true', help='also drive a real Claude Code turn in the guest')
    r.add_argument('--sudo', action='store_true', help='allow the scoped test resolver needed for the outbound checks')
    a = p.parse_args()
    resolve_host(a)
    sys.exit(install(a) if a.command == 'install' else run(a))


if __name__ == '__main__':
    main()
