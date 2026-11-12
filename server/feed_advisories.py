"""Primary-reviewed local advisory checks for security-feed incidents.

Names are product identities, not cross-ecosystem package aliases. Discovery must
use PACKAGES below. Unknown branches, prereleases and vendor builds stay unresolved.
"""
import re
from . import remaining_advisories, november_advisories

REVIEWED_AT = '2026-11-03'
PACKAGES = {
    'python': {'langflow', 'lmdeploy', 'sglang', 'pgadmin4'},
    'npm': {'next'},
    'homebrew': {'atlantis', 'bind', 'freeswitch', 'bitcoin', 'jenkins', 'jenkins-lts', 'epics-base'},
    'composer': {'laravel/framework', 'drupal/core', 'drupal/commerce',
                 'magento/product-community-edition', 'magento/product-enterprise-edition'},
    'maven': {'com.fasterxml.jackson.core:jackson-databind', 'tools.jackson.core:jackson-databind',
              'org.keycloak:keycloak-services'},
    'app': {'lm-studio'},
    'cask': {'clickhouse'},
    'cms': {'wordpress', 'avada', 'richdocumentscode'},
    'gitlab': {'gitlab'},
}
for ecosystem, names in remaining_advisories.PACKAGES.items():
    PACKAGES.setdefault(ecosystem, set()).update(names)
for ecosystem, names in november_advisories.PACKAGES.items():
    PACKAGES.setdefault(ecosystem, set()).update(names)
NAMES = frozenset().union(*PACKAGES.values())
# Each tuple is: identifier, primary source, reviewed range/baseline, fixed versions,
# prerequisites, remediation. Baselines do not claim every older build is exploitable.
ADVISORIES = {
    'drupal/commerce': (
        'drupal-commerce-access-bypass', 'https://www.drupal.org/sa-contrib-2026-254',
        '<2.41; >=3.0.0 <3.3.13', '2.41 (8.x-2.41); 3.3.13',
        'Drupal Commerce routes/entity fields; active exploitation reported by the vendor. Core Drupal updates do not replace Commerce module updates.',
        'Upgrade Commerce on the appropriate branch, redeploy and audit orders for inconsistencies. Enabled modules and remote stores are not verified.'),
    'magento': (
        'magento-blockstrap-patch-review', 'https://www.adobe.com/trust/security/products/commerce/apsb26-153.html',
        'Supported 2.4 branches require October 2026 patch verification', 'Adobe monthly 2026-oct builds; verify isolated patches independently',
        'Commerce/Magento email-template directives. Isolated patches may leave the Composer product version unchanged; package metadata cannot prove patch application.',
        'Apply APSB26-153 for the exact edition/branch, verify patch provenance and redeploy. Ordinary numeric or -p versions require patch review; no fixed result is inferred.'),
    'epics-base': (
        'epics-base-network-memory', 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01',
        '<=7.0.10', '7.0.11',
        'EPICS control-system network message processing; local metadata does not locate controllers or verify network isolation.',
        'Update EPICS Base and rebuild/restart dependent applications; isolate control networks from untrusted access and verify deployed controllers separately.'),
    'lm-studio': (
        'lm-studio-model-download-traversal', 'https://www.vulncheck.com/advisories/lm-studio-before-0.4.22-1-path-traversal-via-model-downloader',
        '<0.4.22+1; bare 0.4.22 has unknown build', '0.4.22+1',
        'Downloading a malicious model repository can plant persistent plugin files. The exact build of bare 0.4.22 cannot be inferred from the display version.',
        'Upgrade and relaunch LM Studio, inspect unexpected plugins and investigate previous malicious model downloads. Updating alone does not remove persistence.'),
    'clickhouse': (
        'clickhouse-server-october-update', 'https://clickhouse.com/docs/resources/changelogs/security-changelog',
        'Reviewed 26.3/26.8/26.9/26.10 branches below their fix require update review', '26.3.62.3-lts; 26.8.36.3-lts; 26.9.27.3-stable; 26.10.3.7-stable',
        'ClickHouse Server with network access; a cask receipt does not prove server mode, execution or cloud exposure.',
        'Update the self-hosted server and restart. ClickHouse reports Cloud/BYOC fixed; this check only reviews local cask metadata.'),
    'keycloak': (
        'keycloak-reset-credentials', 'https://github.com/advisories/GHSA-4gv3-mc9p-5wqc',
        '>=26.0.0 <26.4.15; >=26.5.0 <26.6.6; >=26.7.0 <26.7.2', '26.4.15; 26.6.6; 26.7.2',
        'Keycloak reset-credentials flow; a keycloak-services JAR is not proof of a running controller or reachable reset route.',
        'Upgrade the upstream branch, restart and investigate account resets. Red Hat builds/backports, loaded JVMs and remote services need separate verification.'),
    'jackson': (
        'jackson-databind-polymorphic-types', 'https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-m8xf-2cr7-77ph',
        '2.10.0–2.18.11; 2.19.0–2.21.7; 2.22.0–2.22.3; 3.0.0–3.1.7; 3.2.0–3.2.3', '2.18.12; 2.21.8; 2.22.4; 3.1.8; 3.2.4',
        'Untrusted polymorphic JSON, class-name typing and available classpath gadgets. Metadata does not verify mapper configuration or loaded classes.',
        'Update the Jackson coordinate/branch, rebuild and restart consumers. Shaded/nested copies and running JVMs need separate review.'),
    'wordpress-july': (
        'wordpress-july-sql-rce', 'https://wordpress.org/news/2026/07/wordpress-7-0-2-release/',
        '6.8.x below 6.8.6; 6.9.x below 6.9.5; 7.0.x below 7.0.2 require update review', '6.8.6; 6.9.5; 7.0.2; stable 7.1',
        'Separate SQL injection and REST API issues; 6.8 is affected by the first only. Installed PHP text does not prove deployed code or request routing.',
        'Update WordPress, verify backports and deployed files. Plugins, themes, PHP runtime and server configuration need separate review.'),
    'wordpress-october': (
        'wordpress-october-upgrade-window', 'https://wordpress.org/news/2026/10/wordpress-7-1-4/',
        '7.1.x below 7.1.4 require update review; older branch backports unverified here', '7.1.4',
        'Upgrade-window execution and other October fixes have distinct prerequisites. A July-fixed installation is not necessarily October-fixed.',
        'Apply the October release or verified branch backport, verify deployed files and investigate suspicious staging-folder access.'),
    'avada': (
        'avada-forms-security-update', 'https://avada.com/blog/version-7-16-4-security-update/',
        'Earlier 7.x versions require update review', '7.16.4',
        'Avada Classic Forms uploads; a theme header cannot establish whether the theme/forms are active or uploads executable.',
        'Update Avada Classic, deploy the updated theme and investigate unexpected uploads. Child themes and unrelated themes are not identified by display name alone.'),
    'richdocumentscode': (
        'nextcloud-builtin-code-proxy', 'https://www.cve.org/CVERecord?id=CVE-2026-110447',
        '<26.4.303', '26.4.303',
        'Nextcloud richdocumentscode while CODE is stopped; standalone Collabora and richdocuments are different products. The runtime requires Linux.',
        'Update or remove richdocumentscode and investigate unexpected PHP files. Disabling the app is insufficient. Local source metadata does not inspect containers or remote servers.'),
    'gitlab': (
        'gitlab-regexp-compiler', 'https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/',
        '>=7.0 before fixes on reviewed 18.11 and 19.0–19.5 branches', '18.11.13; 19.0.10; 19.1.9; 19.2.9; 19.3.6; 19.4.3; 19.5.1',
        'Self-managed GitLab CE/EE. Source version text does not verify deployed services, bundled Ruby or a separately compiled runtime.',
        'Update GitLab and Ruby per vendor guidance, redeploy and restart. Inspect worker crashes/Org mode errors; hosted status is not inferred from local files.'),
    'next': (
        'next-october-security-update',
        'https://nextjs.org/blog/nextjs-security-update-october-14-2026',
        '15.5.x <15.5.28; 16.4.x <16.4.1 require update review', '15.5.28; 16.4.1',
        'App Router cache/Server Actions features require configuration review. The SVG RCE is specific to glibc Linux, not a proven macOS exploit.',
        'Upgrade Next.js and its resolved dependencies, rebuild and restart the application. Check sharp separately; no remote deployment or feature configuration is verified.'),
    'langflow': (
        'langflow-october-security-update', 'https://www.ibm.com/support/pages/node/7294467',
        '>=1.0.0 <=1.12.8', '1.13.0',
        'Langflow OSS server; MCP enumeration, auto-login and other exposed features have distinct prerequisites.',
        'Upgrade Langflow to 1.13.0 or later through the vendor, rebuild its environment/image and restart the service; review authentication and prior exposure.'),
    'lmdeploy': (
        'lmdeploy-update-weights-pickle',
        'https://www.vulncheck.com/advisories/lmdeploy-0.9.0-through-0.18.0-unauthenticated-rce-via-update-weights-pickle-deserialization',
        '>=0.9.0 <=0.18.0', 'No fixed release verified as of 2026-11-03',
        'LMDeploy api_server accepts attacker-controlled serialized tensors at /update_weights. Package presence does not establish a reachable server.',
        'Remove untrusted access to the service and review upstream PR #4964. Do not treat a newer version or an unmerged fix as remediation without vendor verification.'),
    'sglang': (
        'sglang-kv-cache-update', 'https://blog.cloudflare.com/kv-cache-exposure-remediation/',
        '0.5.x <0.5.22 require update review', '0.5.22 recommended baseline',
        'Disaggregated prefill/decode with insufficient KV pool capacity; local package metadata cannot prove GPU configuration or cloud tenant isolation.',
        'Update SGLang to the recommended baseline, restart both roles and verify KV pool capacity against context length. Cloudflare reports its hosted incident remediated; this finding concerns local installations.'),
    'pgadmin4': (
        'pgadmin4-october-security-update', 'https://www.pgadmin.org/docs/pgadmin4/9.19/release_notes_9_19.html',
        'Earlier releases require update review', '9.19',
        'Import/Export and authentication/credential handling depend on desktop versus server mode and permissions.',
        'Update pgAdmin and restart it. Review the 9.19 server password-command migration and credentials; updating a PostgreSQL server alone does not update pgAdmin.'),
    'atlantis': (
        'atlantis-october-security-update', 'https://github.com/runatlantis/atlantis/releases/tag/v0.49.0',
        '0.x <0.49.0 require update review', '0.49.0',
        'Webhook, workflow and Terraform plan/apply exposure depends on server settings; metadata does not verify webhook authentication.',
        'Upgrade Atlantis, configure a webhook secret and review the breaking changes: clone-host validation and removal of bundled Terraform/OpenTofu. Restart the service.'),
    'bind': (
        'bind-gss-tsig-memory-corruption', 'https://kb.isc.org/docs/cve-2026-94300',
        '9.11.0 through 9.18.50; 9.20.0 through 9.20.29; 9.21.0 through 9.21.26', '9.20.30; 9.21.27',
        'named receives replayed GSS-TSIG messages while a negotiated key is valid. Client tools alone do not establish a running vulnerable DNS server.',
        'Upgrade to an ISC-supported patched branch and restart named. No 9.18 fix is asserted; verify vendor backports and Supported Preview Edition builds separately.'),
    'freeswitch': (
        'freeswitch-sip-message-api', 'https://github.com/signalwire/freeswitch/security/advisories/GHSA-mg63-h38w-8p9p',
        '<=1.11.2', '1.11.3',
        'A SIP profile accepts inbound MESSAGE; API chat dispatch can invoke process-level commands. Authentication alone is not a complete mitigation.',
        'Upgrade to 1.11.3 or later and restart. Review inbound chat and enable-chat-api-proto settings and investigate prior exposure; other modules require their own configuration review.'),
    'bitcoin': (
        'bitcoin-core-tcp-oom', 'https://bitcoincore.org/en/2026/10/28/disclose-tcp-oom/',
        '29.x <29.5; 30.x <30.4; 31.x <31.2; 32.x <32.1 require update review', '29.5; 30.4; 31.2; 32.1',
        'Bitcoin Core node on non-Linux platforms, including macOS, connected to an untrusted peer; this assessment covers CVE-2026-117350 only.',
        'Update Bitcoin Core within a maintained branch and restart the node. This does not assess wallet signatures, the separate undo-file issue or remote nodes.'),
    'jenkins': (
        'jenkins-october-core-update', 'https://www.jenkins.io/security/advisory/2026-10-28/',
        'Weekly <=2.587; LTS <=2.580.1', 'Weekly 2.588; LTS 2.580.2',
        'Jenkins controller; individual issues depend on permissions, agents or the setup wizard. Formula identity selects weekly versus LTS; plugins are separate.',
        'Upgrade the appropriate Jenkins channel and restart the controller. Review plugins, permissions and setup state; a patched on-disk WAR does not prove the running JVM restarted.'),
    'laravel/framework': (
        'laravel-token-guard', 'https://github.com/laravel/framework/security/advisories/GHSA-f9x3-7vq9-cph6',
        '<12.68.0; >=13.0.0 <13.29.0', '12.68.0; 13.29.0',
        'Standard TokenGuard API authentication with database configurations such as MySQL/MariaDB that mishandle non-string credentials.',
        'Update the installed laravel/framework dependency on the appropriate branch and redeploy/restart workers. Review guard/database configuration; local vendor metadata does not verify production.'),
    'drupal/core': (
        'drupal-field-ui-rce', 'https://www.drupal.org/sa-core-2026-014',
        '>=8.9.0 <10.6.19; >=11.0.0 <11.3.19; >=11.4.0 <11.4.10; 12 prereleases require review', '10.6.19; 11.3.19; 11.4.10 (stable branches)',
        'Field UI enabled with contributed modules or custom code exposing an exploit path; core alone is not directly exploitable.',
        'Update to a patched supported branch or uninstall field_ui as the vendor mitigation. Rebuild/redeploy and verify module state; old unsupported branches and Drupal 12 prereleases need separate review.'),
}


ADVISORIES.update(remaining_advisories.ADVISORIES)
ADVISORIES.update(november_advisories.ADVISORIES)

def numeric(value, parts):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){' + str(parts - 1) + '}', value):
        return None
    return tuple(map(int, value.split('.')))


def branch_state(v, fixes, prefix, old='update_available'):
    if v is None or v[:prefix] not in fixes:
        return 'unresolved'
    return old if v < fixes[v[:prefix]] else 'fixed_for_advisory'


def findings(name, version):
    if name not in NAMES:
        return []
    if name in november_advisories.NAMES:
        row = advisory_row(*november_advisories.states(name, version))
        row['reviewed_at'] = november_advisories.REVIEWED_AT
        return [row]
    if name in remaining_advisories.NAMES:
        return [advisory_row(*remaining_advisories.states(name, version))]
    aliases = {'jenkins-lts': 'jenkins', 'magento/product-community-edition': 'magento',
               'magento/product-enterprise-edition': 'magento',
               'org.keycloak:keycloak-services': 'keycloak',
               'com.fasterxml.jackson.core:jackson-databind': 'jackson',
               'tools.jackson.core:jackson-databind': 'jackson'}
    product = aliases.get(name, name)
    state = 'unresolved'
    v = numeric(version, 3)
    if name == 'next':
        state = branch_state(v, {(15, 5): (15, 5, 28), (16, 4): (16, 4, 1)}, 2)
    elif name == 'langflow' and v is not None:
        if (1, 0, 0) <= v <= (1, 12, 8): state = 'affected_version'
        elif (1, 13, 0) <= v < (2, 0, 0): state = 'fixed_for_advisory'
    elif name == 'lmdeploy' and v is not None:
        if (0, 9, 0) <= v <= (0, 18, 0): state = 'affected_version'
    elif name == 'sglang':
        state = branch_state(v, {(0, 5): (0, 5, 22)}, 2)
    elif name == 'pgadmin4':
        v = numeric(version, 2)
        if v is not None and 1 <= v[0] <= 9:
            state = 'update_available' if v < (9, 19) else 'fixed_for_advisory'
    elif name == 'atlantis':
        state = branch_state(v, {(0,): (0, 49, 0)}, 1)
    elif name == 'bind' and v is not None:
        if (9, 11, 0) <= v <= (9, 18, 50): state = 'affected_version'
        else: state = branch_state(v, {(9, 20): (9, 20, 30), (9, 21): (9, 21, 27)}, 2, 'affected_version')
    elif name == 'freeswitch':
        state = branch_state(v, {(1,): (1, 11, 3)}, 1, 'affected_version')
    elif name == 'bitcoin':
        state = branch_state(numeric(version, 2), {(29,): (29, 5), (30,): (30, 4), (31,): (31, 2), (32,): (32, 1)}, 1)
    elif name == 'jenkins':
        state = branch_state(numeric(version, 2), {(2,): (2, 588)}, 1, 'affected_version')
    elif name == 'jenkins-lts' and v is not None and v[0] == 2:
        if v < (2, 580, 2): state = 'affected_version'
        elif v[:2] == (2, 580): state = 'fixed_for_advisory'
    elif name == 'laravel/framework' and v is not None:
        if v < (12, 68, 0) or (13, 0, 0) <= v < (13, 29, 0): state = 'affected_version'
        elif v[0] in {12, 13}: state = 'fixed_for_advisory'
    elif name == 'drupal/core' and v is not None:
        if ((8, 9, 0) <= v < (10, 6, 19) or (11, 0, 0) <= v < (11, 3, 19)
                or (11, 4, 0) <= v < (11, 4, 10)):
            state = 'affected_version'
        else:
            state = branch_state(v, {(10, 6): (10, 6, 19), (11, 3): (11, 3, 19), (11, 4): (11, 4, 10)}, 2)
    elif name == 'drupal/commerce':
        v = v or ((numeric(version, 2) + (0,)) if numeric(version, 2) else None)
        if v is not None:
            if v < (2, 41, 0) or (3, 0, 0) <= v < (3, 3, 13): state = 'affected_version'
            elif v[0] in {2, 3}: state = 'fixed_for_advisory'
    elif product == 'magento':
        m = re.fullmatch(r'2\.4\.([4-9])-2026-(sep|oct)', version)
        supported = {4, 5, 6, 7, 8, 9} if name.endswith('enterprise-edition') else {7, 8, 9}
        if m and int(m[1]) in supported:
            state = 'fixed_for_advisory' if m[2] == 'oct' else 'affected_version'
    elif name == 'epics-base':
        state = branch_state(v, {(7, 0): (7, 0, 11)}, 2, 'affected_version')
        if v is not None and v < (7, 0, 0): state = 'affected_version'
    elif name == 'lm-studio':
        m = re.fullmatch(r'([0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5})(?:\+([0-9]{1,5}))?', version)
        if m:
            base = numeric(m[1], 3)
            if base < (0, 4, 22): state = 'affected_version'
            elif base[:2] == (0, 4) and base > (0, 4, 22): state = 'fixed_for_advisory'
            elif base == (0, 4, 22) and m[2] is not None: state = 'fixed_for_advisory' if int(m[2]) >= 1 else 'affected_version'
    elif name == 'clickhouse':
        m = re.fullmatch(r'([0-9.]+)-(lts|stable)', version)
        if m:
            v4 = numeric(m[1], 4)
            channels = {(26, 3): 'lts', (26, 8): 'lts', (26, 9): 'stable', (26, 10): 'stable'}
            if v4 and channels.get(v4[:2]) == m[2]:
                state = branch_state(v4, {(26, 3): (26, 3, 62, 3), (26, 8): (26, 8, 36, 3),
                    (26, 9): (26, 9, 27, 3), (26, 10): (26, 10, 3, 7)}, 2)
    elif product == 'keycloak' and v is not None:
        if ((26, 0, 0) <= v < (26, 4, 15) or (26, 5, 0) <= v < (26, 6, 6)
                or (26, 7, 0) <= v < (26, 7, 2)): state = 'affected_version'
        else: state = branch_state(v, {(26, 4): (26, 4, 15), (26, 6): (26, 6, 6), (26, 7): (26, 7, 2)}, 2)
    elif product == 'jackson' and v is not None:
        if name.startswith('com.fasterxml.'):
            if ((2, 10, 0) <= v <= (2, 18, 11) or (2, 19, 0) <= v <= (2, 21, 7)
                    or (2, 22, 0) <= v <= (2, 22, 3)): state = 'affected_version'
            else: state = branch_state(v, {(2, 18): (2, 18, 12), (2, 21): (2, 21, 8), (2, 22): (2, 22, 4)}, 2)
        else:
            if (3, 0, 0) <= v <= (3, 1, 7) or (3, 2, 0) <= v <= (3, 2, 3): state = 'affected_version'
            else: state = branch_state(v, {(3, 1): (3, 1, 8), (3, 2): (3, 2, 4)}, 2)
    elif name == 'wordpress':
        v = v or ((numeric(version, 2) + (0,)) if numeric(version, 2) else None)
        july = branch_state(v, {(6, 8): (6, 8, 6), (6, 9): (6, 9, 5), (7, 0): (7, 0, 2), (7, 1): (7, 1, 0)}, 2)
        october = branch_state(v, {(7, 1): (7, 1, 4)}, 2)
        return [advisory_row('wordpress-july', july), advisory_row('wordpress-october', october)]
    elif name == 'avada':
        state = branch_state(v, {(7,): (7, 16, 4)}, 1)
    elif name == 'richdocumentscode' and v is not None:
        if v < (26, 4, 303): state = 'affected_version'
        else: state = branch_state(v, {(26, 4): (26, 4, 303)}, 2)
    elif name == 'gitlab':
        state = branch_state(v, {(18, 11): (18, 11, 13), (19, 0): (19, 0, 10), (19, 1): (19, 1, 9),
            (19, 2): (19, 2, 9), (19, 3): (19, 3, 6), (19, 4): (19, 4, 3), (19, 5): (19, 5, 1)}, 2, 'affected_version')
        if v is not None and (7, 0, 0) <= v < (18, 11, 0): state = 'affected_version'
    return [advisory_row(product, state)]


def advisory_row(product, state):
    identifier, source, affected, fixed, context, remediation = ADVISORIES[product]
    return dict(id=identifier, state=state, source=source, reviewed_at=REVIEWED_AT,
                 verification='primary_reviewed', affected_range=affected, fixed_versions=fixed,
                 platform='Installed upstream software; platform/configuration prerequisites apply',
                 prerequisites=context, remediation=remediation, enforcement='finding_only',
                 backports='Vendor backports, prereleases, development builds and unreviewed branches require independent verification.')
