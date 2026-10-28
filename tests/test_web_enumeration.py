import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from firebox.modules import web_enumeration


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()
    def log_message(self, *_args):
        pass


class WebEnumerationTests(unittest.TestCase):
    def test_authorization_is_required_and_paths_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "paths.txt"
            wordlist.write_text("/health\n/missing\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                web_enumeration.enumerate_paths("http://127.0.0.1", str(wordlist))
            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = web_enumeration.enumerate_paths(f"http://127.0.0.1:{server.server_port}", str(wordlist), max_requests=2, delay=0.1, confirm_authorized=True)
                self.assertEqual(result["requests_made"], 2)
                self.assertEqual(result["interesting_results"][0]["path"], "/health")
            finally:
                server.shutdown()
                server.server_close()

    def test_delay_and_request_limits_are_validated(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as wordlist:
            wordlist.write("/health\n")
            path = wordlist.name
        with self.assertRaises(ValueError):
            web_enumeration.enumerate_paths("http://127.0.0.1", path, confirm_authorized=True, delay=0.01)
        with self.assertRaises(ValueError):
            web_enumeration.enumerate_paths("http://127.0.0.1", path, confirm_authorized=True, max_requests=501)


if __name__ == "__main__":
    unittest.main()
