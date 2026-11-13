"""Offline advisory matching, never imports/executes inspected software.

This is a reviewed snapshot, not a complete vulnerability database. Commands are
reported intent; artifact identity and OS authorization are separate boundaries.
"""
from dataclasses import dataclass
import re
import shlex

REVIEWED_AT = '2026-10-27'
LITELLM_SOURCE = 'https://docs.litellm.ai/blog/security-incident-oct-21-2026'
PHP_SOURCE = 'https://www.php.net/archive/2026.php#2026-10-21-5'

@dataclass(frozen=True)
class Finding:
    policy: str
    reason: str
    source: str


def assess(name: str, version: str, *, ecosystem: str | None = None) -> Finding | None:
    if ecosystem in {'npm', 'PyPI'}:
        from .local_package_policy import local_policy
        policy = local_policy()
        if policy:
            verdict = policy.assess(ecosystem, name, version)
            if verdict['decision'] == 'block':
                row = next(row for row in verdict['reports'] if row['disposition'] == 'block')
                return Finding('known-malicious-package', 'This package release is listed as malicious in the verified package policy. Read the source report and choose an unaffected release.', row['url'])
    name = re.sub(r'[-_.]+', '-', name.lower())
    if ecosystem in {None, 'PyPI'} and name == 'litellm' and version in {'1.82.7', '1.82.8', '1.107.0'}:
        return Finding('known-malicious-package', 'This exact LiteLLM release is a confirmed malicious distribution. Choose an unaffected release and investigate any previous execution.', LITELLM_SOURCE if version == '1.107.0' else 'https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/')
    if ecosystem in {None, 'npm'} and name == '@subql/common' and version == '5.8.3':
        return Finding('known-malicious-package', 'This exact SubQuery package release contains credential-stealing malware. Choose an unaffected release and investigate any previous execution.', 'https://www.stepsecurity.io/blog/subql-ecosystem-compromised')
    if ecosystem is not None or name != 'php':
        return None
    # Do not interpret vendor suffixes as upstream versions: fixes may be backported.
    if not re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}', version):
        return Finding('unresolved-runtime-version', 'PHP version or vendor patch status is unresolved. Verify the exact artifact against its vendor advisory before installation.', PHP_SOURCE)
    major, minor, patch = map(int, version.split('.'))
    fixed = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
    if (major, minor) in fixed and patch < fixed[(major, minor)]:
        return Finding('vulnerable-runtime', 'This upstream PHP release predates the PHP2Shell fixes (CVE-2026-109618 and CVE-2026-109619). Install a patched release before serving web requests.', PHP_SOURCE)
    if (major, minor) < (8, 2):
        return Finding('unsupported-runtime', 'This PHP branch is no longer supported upstream. Verify a maintained vendor backport or upgrade; age alone does not prove a particular exploit applies.', PHP_SOURCE)
    return None


def command_findings(command: str) -> list[Finding]:
    """Narrow literal install commands, not an interpreter or dependency resolver.

    Only command positions are inspected; printing documentation is not an install.
    Dynamic commands, files/lockfiles and transitive dependencies need inventory.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|\n')
        lexer.whitespace = ' \t\r'
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return []
    if len(words) > 512:
        return []
    segments: list[list[str]] = [[]]
    for word in words:
        if word and all(c in ';&|\n' for c in word):
            segments.append([])
        else:
            segments[-1].append(word)
    found = []
    for args in segments:
        # Minimal common wrappers. Never execute or expand shell input.
        while args and (args[0] in {'sudo', 'env', 'command'} or re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*=[^$`]*', args[0])):
            args = args[1:]
        if not args:
            continue
        exe = args[0].rsplit('/', 1)[-1]
        rest = args[1:]
        if re.fullmatch(r'python(?:3(?:\.\d+)?)?', exe) and rest[:2] == ['-m', 'pip']:
            exe, rest = 'pip', rest[2:]
        if exe == 'uv' and rest[:1] == ['pip']:
            exe, rest = 'pip', rest[1:]
        if (re.fullmatch(r'pip(?:3(?:\.\d+)?)?', exe) and rest[:1] == ['install']) or (exe == 'uv' and rest[:1] in [['add'], ['tool']]):
            for arg in rest[1:]:
                match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]+\])?==([A-Za-z0-9.!+_-]+)', arg)
                if match and (finding := assess(*match.groups(), ecosystem='PyPI')):
                    found.append(finding)
        if exe in {'npm', 'pnpm', 'yarn'} and rest[:1] in [['install'], ['i'], ['add']]:
            for arg in rest[1:]:
                match = re.fullmatch(r'((?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+)@([0-9][A-Za-z0-9.+_-]*)', arg)
                if match and (finding := assess(*match.groups(), ecosystem='npm')):
                    found.append(finding)
        if exe in {'mise', 'asdf', 'phpenv'} and rest[:1] in [['install'], ['use']]:
            for i, arg in enumerate(rest[1:], start=1):
                version = arg[4:] if arg.startswith('php@') else rest[i + 1] if arg == 'php' and i + 1 < len(rest) else None
                if version is not None and (finding := assess('php', version)):
                    found.append(finding)
        if exe == 'phpenv' and len(rest) == 2 and rest[0] == 'install':
            if finding := assess('php', rest[1]):
                found.append(finding)
        if exe == 'brew' and rest[:1] in [['install'], ['reinstall']]:
            for arg in rest[1:]:
                if arg.startswith('php@') and (finding := assess('php', arg[4:])):
                    found.append(finding)
    return list(dict.fromkeys(found))
