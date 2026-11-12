"""Release-provisioned feed URL and verification key, never learned remotely."""
import base64
import json
from pathlib import Path
from urllib.parse import urlsplit


def validate_channel(value):
    if value.get('schema') != 'boxcop.package-channel.v1':
        raise ValueError('Invalid package channel schema')
    url = urlsplit(value['url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Package feed URL must be credential-free HTTPS')
    public = base64.b64decode(value['public_key'], validate=True)
    if len(public) != 32 or type(value['minimum_sequence']) is not int or value['minimum_sequence'] < 1:
        raise ValueError('Invalid feed trust pin')
    return value


def bundled_channel():
    path = Path(__file__).parent / 'assets/package-intelligence/channel.json'
    return validate_channel(json.loads(path.read_bytes())) if path.exists() else None


def bootstrap(channel, directory, *, fetch=None):
    from .package_transport import download
    from .package_intelligence import verify
    from tools.package_service import provision
    channel = validate_channel(channel)
    data = (fetch or download)(channel['url'])
    public = base64.b64decode(channel['public_key'], validate=True)
    policy = verify(data, public)
    if policy.payload['sequence'] < channel['minimum_sequence'] or policy.status()['stale']:
        raise ValueError('Bootstrap snapshot is stale or below release sequence floor')
    provision(directory, data, public)
    return policy
