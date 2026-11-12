"""Read bounded local deployment declarations. Never contact Docker/Kubernetes/Go."""
import re
import yaml
from .remaining_advisories import PACKAGES

IMAGES = {
    'ghcr.io/kubeflow/kfp-frontend': 'kubeflow-frontend',
    'ghcr.io/gitroomhq/postiz-app': 'postiz',
    'rancher/rancher': 'rancher', 'docker.io/rancher/rancher': 'rancher',
    'rancher/fleet': 'fleet', 'docker.io/rancher/fleet': 'fleet',
    'ghcr.io/zitadel/zitadel': 'zitadel',
}
COMPOSE = {'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml', 'compose.json', 'docker-compose.json'}
KUBE_KINDS = {'Pod': 'v1', 'Deployment': 'apps/v1', 'StatefulSet': 'apps/v1', 'DaemonSet': 'apps/v1', 'Job': 'batch/v1', 'CronJob': 'batch/v1', 'List': 'v1'}


class BoundedLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.level = self.nodes = 0

    def compose_node(self, parent, index):
        self.nodes += 1
        self.level += 1
        try:
            if self.level > 32 or self.nodes > 10000 or self.check_event(yaml.AliasEvent):
                raise ValueError('YAML aliases/depth/node limit')
            return super().compose_node(parent, index)
        finally:
            self.level -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError('non-string or duplicate YAML key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def image_identity(value):
    if not isinstance(value, str) or len(value) > 512: raise ValueError('invalid image reference')
    # A digest or interpolation does not prove a tag's version. Retain known
    # repository identities as unresolved, rather than treating tag@digest as fixed.
    reference = value.split('@', 1)[0]
    repository, sep, tag = reference.rpartition(':')
    if not sep or '/' in tag: repository, tag = reference, ''
    product = IMAGES.get(repository)
    if not product: return None
    if '@' in value or not re.fullmatch(r'v?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}', tag): tag = ''
    return product, tag.removeprefix('v')


def containers(document, *, compose=False, depth=0):
    if not isinstance(document, dict): raise ValueError('invalid deployment document')
    if compose:
        services = document.get('services', {})
        if not isinstance(services, dict): raise ValueError('invalid services')
        for service in services.values():
            if not isinstance(service, dict): raise ValueError('invalid service')
            if 'image' in service:
                # A local build can override the advertised image tag.
                value = service['image']
                if 'build' in service and isinstance(value, str): value = value.split('@', 1)[0] + '@local-build'
                yield value
        return
    kind = document.get('kind')
    if not isinstance(kind, str) or kind not in KUBE_KINDS or document.get('apiVersion') != KUBE_KINDS[kind]: return
    if kind == 'List':
        if depth >= 4: raise ValueError('nested deployment list')
        items = document.get('items', [])
        if not isinstance(items, list) or len(items) > 128: raise ValueError('deployment item limit')
        for item in items: yield from containers(item, depth=depth+1)
        return
    spec = document.get('spec', {})
    if kind == 'CronJob': spec = spec.get('jobTemplate', {}).get('spec', {})
    if kind != 'Pod': spec = spec.get('template', {}).get('spec', {})
    for field in ('containers', 'initContainers', 'ephemeralContainers'):
        rows = spec.get(field, [])
        if not isinstance(rows, list) or len(rows) > 128: raise ValueError('container limit')
        for row in rows:
            if not isinstance(row, dict): raise ValueError('invalid container')
            if 'image' in row: yield row['image']


def manifests(scan, fd, path, name):
    data, info = scan.read(fd, name)
    pending = set()
    loader = BoundedLoader(data.decode('utf-8'))
    try:
        count = 0
        while loader.check_data():
            count += 1
            if count > 16: raise ValueError('document limit')
            document = loader.get_data()
            if document is None: continue
            for value in containers(document, compose=name in COMPOSE):
                match = image_identity(value)
                if match: pending.add(match)
                if len(pending) > 128: raise ValueError('image limit')
    finally:
        loader.dispose()
    for product, version in sorted(pending):
        if not scan.available(): return
        scan.record(product, version, path/name, 'deployment_image_declaration', data, info)


def go_mod(scan, fd, path, name):
    data, info = scan.read(fd, name)
    text = data.decode('utf-8')
    # Interpret only literal require directives. Do not run go list/download,
    # resolve replacements, evaluate workspaces, or interpret go.sum as selection.
    pending = {}
    section = None
    replacement = False
    for raw in text.splitlines():
        line = raw.split('//', 1)[0].strip()
        if not line: continue
        if line == ')': section = None; continue
        if line.endswith('('):
            if section is not None: raise ValueError('nested go directive')
            section = line[:-1].strip()
            if section in {'replace', 'exclude'}: replacement = True
            continue
        directive = re.match(r'^(require|replace|exclude)\s+(.+)$', line)
        if directive and directive[1] in {'replace', 'exclude'}: replacement = True
        value = directive[2] if directive and directive[1] == 'require' else line if section == 'require' else None
        if value is None: continue
        tokens = value.split()
        if len(tokens) != 2: raise ValueError('unsupported go require')
        module, version = tokens
        if any(c in module + version for c in '"`'):
            raise ValueError('quoted Go requirements unsupported')
        if module not in PACKAGES['go']: continue
        if module in pending: raise ValueError('duplicate Go requirement')
        pending[module] = version[1:] if re.fullmatch(r'v[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}', version) else ''
    if section is not None: raise ValueError('unterminated Go directive')
    for module, version in pending.items():
        scan.record(module, '' if replacement else version, path/name, 'go_module_declaration', data, info)


def inspect(scan, fd, path, name):
    if name == 'go.mod':
        go_mod(scan, fd, path, name)
        return True
    if name in COMPOSE or name.endswith(('.k8s.json', '.k8s.yaml', '.k8s.yml')):
        manifests(scan, fd, path, name)
        return True
    return False
