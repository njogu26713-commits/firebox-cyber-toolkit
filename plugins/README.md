# Firebox manual plugins

Place trusted Python plugin files in this directory. Firebox loads `*.py` files automatically at startup. A plugin must define:

```python
def register(subparsers):
    parser = subparsers.add_parser("my-command", help="Describe the command")
    parser.add_argument("--value", required=True)
    parser.set_defaults(_plugin_handler=run)


def run(args):
    return {"value": args.value}
```

`run(args)` may return a JSON-serializable value; Firebox prints it using the normal readable formatter and supports `--json` and `--report` when those options are added by the plugin. The plugin runs with the same operating-system permissions as the user running Firebox. Only add code you have reviewed and trust. Plugins can read files, make network connections, and execute code.

The following commands help inspect plugins:

```bash
firebox plugins list
```

For an isolated plugin directory:

```bash
FIREBOX_PLUGIN_DIR=/secure/path/plugins firebox plugins list
```

A broken plugin is reported as an error and does not prevent built-in commands from loading. Plugin command names must not collide with built-in command names.
