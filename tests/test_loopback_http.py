import socket

import pytest

from server.package_proxy import RegistryServer
from server.package_scripts import ProxyServer


@pytest.mark.parametrize('server_type', [RegistryServer, ProxyServer])
def test_listener_starts_without_hostname_resolution(monkeypatch, server_type):
    def unexpected_lookup(*args, **kwargs):
        raise AssertionError('Loopback startup must not resolve hostnames')

    monkeypatch.setattr(socket, 'getfqdn', unexpected_lookup)
    monkeypatch.setattr(socket, 'gethostbyaddr', unexpected_lookup)
    with server_type(None, port=0) as server:
        assert server.server_name == '127.0.0.1'
        assert server.server_port == server.server_address[1] > 0
        with socket.create_connection(server.server_address, timeout=1):
            pass
