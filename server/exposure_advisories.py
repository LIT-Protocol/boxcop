"""Reviewed exposure snapshot. Metadata findings never authorize executable policy.

Ranges describe upstream releases only. Vendor suffixes/backports and unknown
channels remain unresolved. No network requests, imports of inspected code or feed
instructions are used by this module.
"""
import re
from .supply_chain import assess
from . import feed_advisories

REVIEWED_AT = '2026-10-27'
PHP = 'https://www.php.net/archive/2026.php'
NODE = 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'
RUBY = 'https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/'
PILLOW = 'https://github.com/python-pillow/Pillow/security/advisories/GHSA-5x8w-8jj5-q52h'
WASM = 'https://github.com/bytecodealliance/wasmtime/security/advisories/'
POPCORN = 'https://labs.eye.security/cve-2026-30612-a-vulnerability-in-time4popcorn-popcorntime/'
BROTLI = 'https://github.com/google/brotli/releases/tag/v1.2.1'
CHROME = 'https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02107719452.html'
CHROME_NOVEMBER = 'https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop.html'
ELECTRUM = 'https://github.com/spesmilo/electrum/security/advisories/GHSA-6jp4-8v48-cc5v'
MOZILLA = 'https://www.mozilla.org/en-US/security/advisories/'


def numeric(value, parts=3):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){' + str(parts-1) + '}', value):
        return None
    return tuple(map(int, value.split('.')))


def findings(name, version, *, architecture='unknown', channel='unknown'):
    """Inventory-only facts; fixed_for_advisory never means safe or deployed."""
    name = name.lower()
    if name in feed_advisories.NAMES:
        return feed_advisories.findings(name, version)
    name = re.sub(r'[-_.]+', '-', name)
    if name in feed_advisories.NAMES:
        return feed_advisories.findings(name, version)
    rows = []
    v = numeric(version)

    def add(identifier, state, source, affected, fixed, context, remediation, platform='macOS and other upstream platforms', verified=True):
        rows.append(dict(id=identifier, state=state, source=source, reviewed_at=REVIEWED_AT,
                         verification='primary_reviewed' if verified else 'unresolved_source',
                         affected_range=affected, fixed_versions=fixed, platform=platform,
                         prerequisites=context, remediation=remediation,
                         enforcement='finding_only', backports='Vendor backports require independent artifact/vendor verification.'))

    def branches(mapping, prefix=2):
        if v is None or v[:prefix] not in mapping: return 'unresolved'
        return 'affected_version' if v < mapping[v[:prefix]] else 'fixed_for_advisory'

    if name == 'php':
        add('php2shell', branches({(8,2):(8,2,35), (8,3):(8,3,36), (8,4):(8,4,27), (8,5):(8,5,12)}), PHP,
            '8.2 <8.2.35; 8.3 <8.3.36; 8.4 <8.4.27; 8.5 <8.5.12', '8.2.35, 8.3.36, 8.4.27, 8.5.12',
            'Serving web requests; older branches and vendor backports need review.',
            'Update the runtime through its vendor and restart every web worker. Verify vendor backports separately.')
        add('php-session-upload-configuration', 'configuration_review', PHP, 'Configuration-dependent; exact deployed behavior unknown', 'No fixed version asserted in this snapshot',
            'Upload progress enabled, non-php serializer configured, application switches serializer to php at runtime.',
            'Review session.upload_progress.enabled and application serializer changes. Follow the vendor mitigation and restart workers; a version check cannot verify this setting.')
    elif name in {'node', 'nodejs'}:
        add('node-brotli', branches({(22,):(22,23,4), (24,):(24,22,1), (26,):(26,12,1)}, 1), NODE,
            '22.x <22.23.4; 24.x <24.22.1; 26.x <26.12.1', '22.23.4, 24.22.1, 26.12.1',
            'Application decompresses attacker-controlled Brotli input. Embedded decoder version is not inferred from an unrelated system library.',
            'Update Node, rebuild bundled/embedded runtimes and restart processes using the old runtime.')
    elif name == 'brotli':
        add('brotli-decoder', 'unresolved' if v is None else ('update_available' if v < (1,2,1) else 'fixed_for_advisory'), BROTLI,
            'Release 1.2.1 fixes CVE-2026-111497; lower-version/backport exposure requires vendor review', '1.2.1',
            'Decoding untrusted Brotli data; statically bundled copies may differ from installed package metadata.',
            'Update/rebuild applications embedding Brotli and restart them. Verify each bundled copy.')
    elif name == 'pillow':
        state = 'unresolved' if v is None or (12,3,0) < v < (13,0,0) else ('affected_version' if v <= (12,3,0) else 'fixed_for_advisory')
        add('pillow-fpx', state, PILLOW, '<=12.3.0', '13.0.0',
            'Opening untrusted FPX images with optional olefile installed. Exploit demonstration was Linux x86_64; no macOS exploit reproduced.',
            'Upgrade Pillow, rebuild packaged Python environments and restart consumers; verify optional olefile and untrusted-image exposure.')
    elif name == 'ruby':
        for identifier, patch in [('regexp-double-free',0), ('regexp-size-overflow',8), ('regexp-repeat-overflow',9)]:
            add('ruby-'+identifier, branches({(4,0):(4,0,patch),(3,4):(3,4,12),(3,3):(3,3,13)}), RUBY,
                f'4.0 <4.0.{patch}; 3.4 <3.4.12; 3.3 <3.3.13', f'4.0.{patch}, 3.4.12, 3.3.13',
                'Compiling attacker-controlled regular expressions; timeout alone does not prevent compiler corruption.',
                'Update Ruby to a release containing all fixes and restart applications. Review vendor-patched embedded Ruby separately.')
    elif name in {'wasmtime', 'wasmtime-cli'}:
        affected = v is not None and (v < (36,0,19) or (37,0,0) <= v < (43,0,0))
        add('wasmtime-ssa', 'unresolved' if v is None else ('affected_version' if affected else 'fixed_for_advisory'), WASM+'GHSA-897f-g5gm-fmxm',
            '<36.0.19; >=37.0.0 <43.0.0', '36.0.19; 43.0.0+', 'Cranelift backend compiles untrusted Wasm modules; all architectures.',
            'Update Wasmtime and rebuild embedding applications. Restart engines and regenerate compiled module caches.')
        affected = v is not None and (v < (36,0,19) or (37,0,0) <= v < (48,0,7) or (49,0,0) <= v < (49,0,4))
        state = 'unresolved' if v is None or architecture not in {'arm64','aarch64','x86_64'} else ('not_applicable_architecture' if architecture == 'x86_64' else ('affected_version' if affected else 'fixed_for_advisory'))
        add('wasmtime-arm64-branch', state, WASM+'GHSA-mghf-wjfp-p5xm', '<36.0.19; >=37.0.0 <48.0.7; >=49.0.0 <49.0.4', '36.0.19, 48.0.7, 49.0.4',
            'Cranelift on aarch64 compiling untrusted Wasm; a host architecture alone does not verify an embedded binary architecture.',
            'Update/rebuild the ARM64 engine, restart consumers and regenerate compiled caches.', platform='aarch64 / ARM64')
    elif name == 'electrum':
        add('electrum-rbf', 'unresolved' if v is None else ('affected_version' if v < (4,8,3) else 'fixed_for_advisory'), ELECTRUM,
            '<4.8.3', '4.8.3', 'Untrusted server substitutes an unconfirmed transaction; user signs a fee bump.',
            'Update and relaunch Electrum; independently verify output addresses and amounts before signing. Clipboard protection does not validate transactions.')
    elif name == 'chrome':
        v4 = numeric(version, 4)
        add('chrome-october-update', 'unresolved' if v4 is None else ('update_available' if v4 < (156,0,8078,79) else 'fixed_for_advisory'), CHROME,
            'Earlier stable builds require update review; not every CVE affects every earlier version', '156.0.8078.79/.80 on Mac',
            'Browser processes may still run old code after an on-disk update.', 'Update Chrome and fully relaunch it; verify the running build.', platform='macOS stable channel')
        rows[-1]['reviewed_at'] = '2026-11-03'
        add('chrome-november-update', 'unresolved' if v4 is None else ('update_available' if v4 < (157,0,8103,38) else 'fixed_for_advisory'), CHROME_NOVEMBER,
            'Earlier stable builds require update review; no per-CVE affected range inferred', '157.0.8103.38/.39 on Mac',
            'November stable release; on-disk metadata does not establish the running browser build.',
            'Update Chrome and fully relaunch it. Chromium/Electron copies in other apps require their own vendor fixes.', platform='macOS stable channel')
        rows[-1]['reviewed_at'] = '2026-11-04'
    elif name == 'firefox':
        # Channel must come from explicit app metadata, not a guessed version branch.
        vfire = numeric(version) or (numeric(version,2) + (0,) if numeric(version,2) else None)
        fixed, advisory = ((159,0,0),'mfsa2026-118/') if channel == 'release' else (((115,44,0),'mfsa2026-119/') if vfire and vfire[0] == 115 else ((153,6,0),'mfsa2026-120/'))
        state = 'unresolved' if vfire is None or channel not in {'release','esr'} or (channel == 'esr' and vfire[0] not in {115,153}) else ('update_available' if vfire < fixed else 'fixed_for_advisory')
        add('firefox-october-update', state, MOZILLA+advisory, 'Earlier releases in the verified release/ESR channel require review', '.'.join(map(str,fixed)),
            'Release versus ESR channel must be verified; on-disk version does not establish running code.',
            'Use the browser updater for the correct channel and fully relaunch Firefox.')
    elif name in {'time4popcorn-helper','time4popcorn'}:
        add('time4popcorn-updater', 'helper_review' if name.endswith('helper') else 'identity_review', POPCORN,
            'Abandoned Time4Popcorn fork; unrelated modern Popcorn Time software is excluded', 'No fixed abandoned release',
            'PT.updd is a root updater. File/name presence alone does not prove its provenance or running state.',
            'Verify the helper and launch daemon, disable the abandoned updater using the researcher guidance, and remove the abandoned app. Root helper activity is outside normal-user enforcement.', platform='macOS')
    else:
        match = assess(name, version)
        if match:
            add(match.policy, 'affected_version', match.source, 'Exact reviewed malicious distribution', 'Choose a reviewed replacement', match.reason,
                'Replace the distribution and investigate previous execution; rotate exposed credentials if needed.')
    return rows
