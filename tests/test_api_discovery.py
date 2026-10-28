import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from firebox.modules import api_discovery


class ApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/openapi.json":
            body = b'{"openapi":"3.0.0","info":{"title":"Synthetic API"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *_args):
        pass


class ApiDiscoveryTests(unittest.TestCase):
    def test_finds_openapi_document_without_crawling(self):
        server = HTTPServer(("127.0.0.1", 0), ApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = api_discovery.discover(f"http://127.0.0.1:{server.server_port}", "/openapi.json,/missing")
            self.assertEqual(result["requests_made"], 2)
            self.assertEqual(result["documents_found"][0]["documentation_markers"], ["OpenAPI"])
            self.assertTrue(result["scope"].startswith("Read-only bounded"))
        finally:
            server.shutdown()
            server.server_close()

    def test_rejects_too_many_paths(self):
        with self.assertRaises(ValueError):
            api_discovery.discover("http://127.0.0.1", ",".join(f"/{i}" for i in range(9)))


if __name__ == "__main__":
    unittest.main()
