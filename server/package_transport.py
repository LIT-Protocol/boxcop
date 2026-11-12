"""Bounded, credential-free-by-default HTTPS transport for public feed metadata."""
from urllib.parse import urlsplit
import httpx
import time

from .package_intelligence import MAX_BYTES


def download(url, *, token=None, limit=MAX_BYTES, params=None, include_headers=False):
    for attempt in range(3):
        try:
            return _download(url, token=token, limit=limit, params=params, include_headers=include_headers)
        except httpx.HTTPStatusError as error:
            if error.response.status_code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)


def _download(url, *, token=None, limit=MAX_BYTES, params=None, include_headers=False):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username:
        raise ValueError('Feeds require HTTPS without URL credentials')
    headers = {'User-Agent': 'BoxCop-Package-Intelligence/1', 'Accept': 'application/json'}
    if token:
        if parsed.netloc != 'api.github.com':
            raise ValueError('Refusing to send GitHub credentials to another origin')
        headers['Authorization'] = 'Bearer ' + token
    with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
        with client.stream('GET', url, params=params, headers=headers) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError('Feed download exceeds limit')
            return (bytes(data), dict(response.headers)) if include_headers else bytes(data)
