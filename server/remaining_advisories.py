"""Reviewed advisory identities for the final local feed review, not enforcement."""
import re

PACKAGES = {
    'homebrew': {'cloudflared'},
    'app': {'cloudflare-warp', 'cursor-browser', 'vscode-browser', 'claude-browser', 'codex-browser'},
    'source': {'goahead'},
    'go': {'github.com/labstack/echo/v4', 'github.com/labstack/echo/v5'},
    'image': {'kubeflow-frontend', 'postiz', 'rancher', 'fleet', 'zitadel'},
}
NAMES = frozenset().union(*PACKAGES.values())
CF = 'https://blog.cloudflare.com/emudhra-certificate-compromise/'
EMBRACE = 'https://forever.security/blog/embrace-hacking-5-ai-assistants-embedded-browsers-technical'
ADVISORIES = {
    'echo': ('echo-proxy-websocket-auth',
        'https://github.com/labstack/echo/security/advisories/GHSA-cxf3-9h37-7rr8',
        'v4 >=4.0.0 <4.16.1; v5 >=5.0.0 <5.4.1', '4.16.1; 5.4.1',
        'Proxy middleware, rejected upgrade with a persistent upstream connection, and route-only authorization. go.mod is a dependency declaration, not a built binary inventory.',
        'Update the matching Echo module and rebuild/redeploy. Verify selected modules, workspace overrides and upstream authorization independently.'),
    'goahead': ('goahead-october-update', 'https://github.com/embedthis/goahead/releases/tag/v6.1.1',
        '6.x before 6.1.1 requires update review', '6.1.1',
        'Eleven fixes with distinct TLS, authentication and CGI prerequisites. Source metadata does not identify firmware or a running server.',
        'Update GoAhead, rebuild consumers and obtain firmware from device manufacturers. Check TLS backend and enabled features; a local checkout does not patch devices.'),
    'kubeflow-frontend': ('kubeflow-volume-artifact-traversal',
        'https://github.com/kubeflow/pipelines/security/advisories/GHSA-2fg9-fx2f-439r',
        '<=2.17.3', '2.18.0',
        'Reachable volume artifact handler and a mounted volume; authentication/namespace requirements depend on deployment. This finding covers CVE-2026-118758, not every companion advisory.',
        'Upgrade the frontend and artifact-serving components to the reviewed release, redeploy, verify authentication and review companion advisories. Image tags are desired state, not proof of deployed bytes.'),
    'postiz': ('postiz-october-update', 'https://github.com/gitroomhq/postiz-app/releases/tag/v2.25.3',
        'Earlier 2.x releases require update review', '2.25.3',
        'Self-hosted Postiz token signing and media handling; registered-user access. The repository package.json version is not the product release.',
        'Upgrade and redeploy Postiz, investigate previous exposure and rotate potentially exposed secrets. Verify image identity and running pods independently.'),
    'rancher': ('rancher-october-update', 'https://documentation.suse.com/cloudnative/rancher-manager/v2.15/en/security/cves.html',
        'Reviewed 2.11–2.15 branches below October baselines', '2.11.19; 2.12.15; 2.13.11; 2.14.7; 2.15.3',
        'Management cluster authorization and proxy issues. Fleet is separately versioned; a Rancher image tag does not prove Fleet is patched.',
        'Upgrade Rancher and the corresponding Fleet release, redeploy, and review management-cluster secrets/roles for compromise.'),
    'fleet': ('fleet-october-update', 'https://documentation.suse.com/cloudnative/rancher-manager/v2.15/en/security/cves.html',
        'Reviewed 0.13–0.16 branches below October baselines', '0.13.17; 0.14.12; 0.15.8; 0.16.3',
        'Fleet controller privileges and cluster registration; controller image references do not verify running cluster state or agent images.',
        'Upgrade Fleet with the supported Rancher release; verify controller rollout, cluster credentials and tenant isolation.'),
    'zitadel': ('zitadel-login-v2-review', 'https://github.com/zitadel/zitadel/security/advisories/GHSA-qj3q-235g-qr6w',
        '3.0.0–3.4.15 device authorization; 4.0.0–<4.19.5 Login V2', '4.19.5; no 3.x fixed baseline encoded',
        'Login V2 host headers, initial credentials and device authorization have distinct prerequisites. Container configuration and actual login service versions remain unverified.',
        'Update ZITADEL and Login V2 components, verify proxy header handling and redeploy. Review account changes and revoke suspect sessions.'),
    'cloudflared': ('cloudflared-emudhra-update', CF,
        'Reviewed 2026.x releases before 2026.10.2 require update', '2026.10.2',
        'cloudflared certificate verification only; unrelated OS, browser, mTLS and custom trust stores are not checked.',
        'Upgrade and restart cloudflared, rebuild container images and verify the actual application TLS path. Do not disable certificate verification.'),
    'cloudflare-warp': ('warp-emudhra-update', CF,
        'Reviewed 2026.x macOS releases before 2026.8.2115.0 require update', '2026.8.2115.0',
        'Cloudflare macOS client update baseline only; installation does not establish active Gateway routing or system-wide certificate distrust.',
        'Update and restart the Cloudflare client, verify intended routing and review each custom trust store separately. Do not disable TLS verification.'),
    'embedded-browser': ('embedded-browser-security-review', EMBRACE,
        'Installed implicated app; exact embedded-browser patch status unverified', 'Verify vendor build; no desktop-version cutoff encoded',
        'EMBRACE reports distinct browser bridge, local-file and address-spoofing issues. App presence is not evidence of exploitability or enabled browser features.',
        'Verify the current vendor fix for the embedded browser; avoid untrusted local HTML previews and pages until verified. Agent command hooks do not mediate all browser file access or navigation.'),
}


def states(name, version):
    product = 'echo' if name.startswith('github.com/labstack/echo/') else 'embedded-browser' if name.endswith('-browser') else name
    state = 'unresolved'
    match = re.fullmatch(r'[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}', version)
    v = tuple(map(int, version.split('.'))) if match else None
    fixes = {}
    if product == 'echo':
        major, fix = (4, (4, 16, 1)) if name.endswith('/v4') else (5, (5, 4, 1))
        if v and v[0] == major: state = 'affected_version' if v < fix else 'fixed_for_advisory'
    elif name == 'kubeflow-frontend' and v and v[0] == 2:
        if v <= (2, 17, 3): state = 'affected_version'
        elif v >= (2, 18, 0): state = 'fixed_for_advisory'
    elif name == 'zitadel' and v:
        if (3, 0, 0) <= v <= (3, 4, 15) or (4, 0, 0) <= v < (4, 19, 5): state = 'affected_version'
        elif v[0] == 4 and v >= (4, 19, 5): state = 'fixed_for_advisory'
    elif name == 'rancher': fixes = {(2, 11): (2, 11, 19), (2, 12): (2, 12, 15), (2, 13): (2, 13, 11), (2, 14): (2, 14, 7), (2, 15): (2, 15, 3)}
    elif name == 'fleet': fixes = {(0, 13): (0, 13, 17), (0, 14): (0, 14, 12), (0, 15): (0, 15, 8), (0, 16): (0, 16, 3)}
    elif name in {'postiz', 'goahead', 'cloudflared'} and v:
        major, fix = {'postiz': (2, (2, 25, 3)), 'goahead': (6, (6, 1, 1)), 'cloudflared': (2026, (2026, 10, 2))}[name]
        if v[0] == major: state = 'update_available' if v < fix else 'fixed_for_advisory'
    elif name == 'cloudflare-warp' and re.fullmatch(r'2026\.[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}', version):
        state = 'update_available' if tuple(map(int, version.split('.'))) < (2026, 8, 2115, 0) else 'fixed_for_advisory'
    if v and v[:2] in fixes: state = 'update_available' if v < fixes[v[:2]] else 'fixed_for_advisory'
    return product, state
