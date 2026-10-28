import contextlib
import io
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from firebox.cli import main
from firebox.modules import network, web_security

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "sid=example; Secure; HttpOnly")
        self.end_headers()
    def log_message(self, *_args):
        pass

class CliAndWebTests(unittest.TestCase):
    def test_cli_rejects_invalid_ports(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main(["network", "ports", "--target", "127.0.0.1", "--ports", "0"])
        self.assertNotEqual(exc.exception.code, 0)

    def test_dns_failure_is_reported(self):
        result = network.resolve("does-not-exist.invalid")
        self.assertEqual(result["addresses"], [])
        self.assertTrue(result["error"])

    def test_web_checker_local_http_and_error(self):
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = web_security.check(f"http://127.0.0.1:{server.server_port}")
            self.assertEqual(result["status"], 200)
            self.assertIn("X-Content-Type-Options", result["security_headers"]["present"])
            self.assertEqual(len(result["cookies"]), 1)
        finally:
            server.shutdown()
            server.server_close()
        failure = web_security.check("http://127.0.0.1:1", timeout=0.1)
        self.assertTrue(failure["error"])

    def test_json_report_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "file.txt"
            report = Path(directory) / "report.json"
            target.write_text("content", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(["hash", "generate", "--file", str(target), "--json", "--report", str(report)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["sha256"], json.loads(report.read_text())["sha256"])

if __name__ == "__main__":
    unittest.main()
