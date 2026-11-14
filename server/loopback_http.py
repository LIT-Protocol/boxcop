"""HTTP listeners whose startup does not depend on hostname resolution."""
from http.server import ThreadingHTTPServer
from socketserver import TCPServer


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind calls getfqdn(), which can stall on macOS
        # runners. These listeners bind a numeric loopback address and have
        # no need for a DNS-derived server name.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]
