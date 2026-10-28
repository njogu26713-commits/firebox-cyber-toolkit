import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from firebox.cli import main


class PluginTests(unittest.TestCase):
    def test_manual_plugin_loads_and_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_dir = Path(directory) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "hello.py").write_text(
                "def register(subparsers):\n"
                "    parser = subparsers.add_parser('hello')\n"
                "    parser.add_argument('--value', required=True)\n"
                "    parser.set_defaults(_plugin_handler=run)\n\n"
                "def run(args):\n"
                "    return {'plugin_value': args.value}\n",
                encoding="utf-8",
            )
            previous = os.environ.get("FIREBOX_PLUGIN_DIR")
            os.environ["FIREBOX_PLUGIN_DIR"] = str(plugin_dir)
            try:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    code = main(["hello", "--value", "works"])
                self.assertEqual(code, 0)
                self.assertIn("Plugin Value: works", output.getvalue())
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    code = main(["plugins", "list", "--json"])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(output.getvalue())["plugins"][0]["status"], "valid")
            finally:
                if previous is None:
                    os.environ.pop("FIREBOX_PLUGIN_DIR", None)
                else:
                    os.environ["FIREBOX_PLUGIN_DIR"] = previous


if __name__ == "__main__":
    unittest.main()
