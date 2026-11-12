"""November feed additions: local metadata advice, never execution policy."""
import re

REVIEWED_AT = '2026-11-04'
PACKAGES = {
    'npm': {'@better-auth/expo', 'better-auth', 'node-red'},
    'homebrew': {'freerdp', 'tailscale', 'headscale'},
    'app': {'tailscale', 'teamviewer'},
}
NAMES = frozenset().union(*PACKAGES.values())
BETTER_AUTH = 'https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg'
ADVISORIES = {
    '@better-auth/expo': ('better-auth-expo-signing', BETTER_AUTH,
        '>=1.4.0-beta.6 <1.7.16; >=1.8.0-beta.0 <1.8.0-beta.5', '1.7.16; 1.8.0-beta.5',
        'Server registers expo(); cookie-cache impersonation and wildcard origins have additional settings. Package presence does not establish plugin registration.',
        'Update both @better-auth/expo and better-auth, redeploy and rotate the application secret if the endpoint was reachable. Old signatures survive a package update.'),
    'better-auth': ('better-auth-core-expo-review', BETTER_AUTH,
        '<1.7.16; >=1.8.0-beta.0 <1.8.0-beta.5', '1.7.16; 1.8.0-beta.5',
        'Expo server plugin must be registered for the signing endpoint. Core package metadata alone does not establish that prerequisite or the companion package version.',
        'Update both better-auth and @better-auth/expo, redeploy and rotate the application secret if the endpoint was reachable. Verify plugin registration and trusted origins.'),
    'freerdp': ('freerdp-security-update', 'https://github.com/FreeRDP/FreeRDP/releases/tag/3.32.2',
        'Earlier 3.x builds require update review; individual advisories have different prerequisites', '3.32.2',
        'Client, server and proxy features process untrusted RDP traffic. A Homebrew receipt cannot identify every embedded library or verify certificate settings.',
        'Update FreeRDP, rebuild embedding clients and restart sessions/services. Check the individual release advisories for enabled features and vendor backports.'),
    'node-red': ('node-red-admin-auth-review', 'https://nodered.org/docs/user-guide/runtime/securing-node-red',
        'Configuration-dependent at any package version', 'No npm version establishes adminAuth or network isolation',
        'The editor/admin API permits flow deployment unless secured. Siemens CVE-2026-58115 concerns Industrial OS devices; V4.3.4-1 is not an npm Node-RED fix version.',
        'Verify adminAuth and network access restrictions in the running service; review unexpected flows. Secure HTTP nodes separately. No settings.js is executed or treated as proof of runtime configuration.'),
    'tailscale': ('tailscale-ssh-serve-update', 'https://tailscale.com/security-bulletins',
        'Earlier 1.x releases require review against TS-2026-014 through TS-2026-017', '1.104.4',
        'SSH forwarding/session handling and Serve have distinct configuration and platform prerequisites. App presence does not prove SSH server support or active Serve configuration.',
        'Update and restart affected Tailscale nodes; review SSH/Serve settings. This baseline does not resolve every Tailworm report or patch a Headscale server.'),
    'headscale': ('headscale-tailworm-update', 'https://github.com/juanfont/headscale/releases/tag/v0.29.7',
        'Earlier 0.29.x releases require update review', '0.29.7',
        'Headscale control-server release fixes; installed metadata does not verify a running server or node versions.',
        'Update and restart Headscale, and independently update Tailscale nodes to 1.104.4 or newer. A server update does not apply node SSH fixes.'),
    'teamviewer': ('teamviewer-macos-client-update', 'https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/',
        'macOS 15.x before 15.83; 14.7 before 14.7.48868; 13.2 before 13.2.154007', '15.83; 14.7.48868; 13.2.154007 (macOS)',
        'TV-2026-1011: remote-session/recording decoder issues and local privileged-helper race. Full Client and Host differ; Remote Management add-ons are separately versioned.',
        'Update the macOS Full Client/Host and relaunch. Verify Remote Management add-ons against TV-2026-1012 separately; Windows legacy builds do not establish a macOS fix.'),
}


def states(name, version):
    state = 'unresolved'
    # TeamViewer legacy macOS builds use six digits. No vendor suffix stripping.
    match = re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}', version)
    v = tuple(map(int, version.split('.'))) if match else None
    if name in {'@better-auth/expo', 'better-auth'}:
        if v and v[0] == 1:
            if (name == 'better-auth' or v >= (1, 4, 0)) and v < (1, 7, 16):
                state = 'affected_version'
            elif v[:2] == (1, 7) and v >= (1, 7, 16):
                state = 'fixed_for_advisory'
        beta = re.fullmatch(r'1\.(4|8)\.0-beta\.(0|[1-9][0-9]{0,4})', version)
        if beta:
            minor, number = map(int, beta.groups())
            if minor == 8:
                state = 'affected_version' if number < 5 else 'fixed_for_advisory'
            elif name == 'better-auth' or number >= 6:
                state = 'affected_version'
    elif name == 'node-red':
        state = 'configuration_review'
    elif name in {'freerdp', 'tailscale', 'headscale'} and v:
        prefix, fixed = {'freerdp': ((3,), (3, 32, 2)),
                         'tailscale': ((1,), (1, 104, 4)),
                         'headscale': ((0, 29), (0, 29, 7))}[name]
        if v[:len(prefix)] == prefix:
            state = 'update_available' if v < fixed else 'fixed_for_advisory'
    elif name == 'teamviewer':
        # The current release is also advertised as the two-component 15.83.
        if re.fullmatch(r'15\.[0-9]{1,6}', version):
            v = tuple(map(int, version.split('.'))) + (0,)
        if v:
            fixed = (15, 83, 0) if v[0] == 15 else {
                (14, 7): (14, 7, 48868), (13, 2): (13, 2, 154007)}.get(v[:2])
            if fixed:
                state = 'update_available' if v < fixed else 'fixed_for_advisory'
    return name, state
