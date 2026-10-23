#!/usr/bin/env python3
"""
Generate manifests/frontend/configmap.yaml from frontend source files.
Called by scripts/build-dashboard-configmap.sh.

Usage:
    python3 scripts/_gen_configmap.py frontend/index.html frontend/app.js \
        frontend/style.css manifests/frontend/configmap.yaml
"""
import sys
import pathlib


def indent(text, spaces=4):
    pad = " " * spaces
    return "\n".join(pad + line for line in text.splitlines())


def main():
    if len(sys.argv) < 5:
        print("Usage: _gen_configmap.py <index.html> <app.js> <style.css> <output.yaml>")
        sys.exit(1)

    html_path, js_path, css_path, out_path = sys.argv[1:5]

    sources = [
        ("index.html", html_path),
        ("app.js",     js_path),
        ("style.css",  css_path),
    ]

    parts = []
    for name, path in sources:
        content = pathlib.Path(path).read_text(encoding="utf-8")
        parts.append(f"  {name}: |\n{indent(content, 4)}")

    data_block = "\n".join(parts)

    configmap = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: rtm-dashboard-html
  namespace: shop
  labels:
    app: rtm-dashboard
    app.kubernetes.io/part-of: rtm-k8s
data:
{data_block}
"""

    pathlib.Path(out_path).write_text(configmap, encoding="utf-8")
    print(f"ConfigMap written to {out_path}")
    for name, path in sources:
        size = len(pathlib.Path(path).read_text(encoding="utf-8"))
        print(f"  {name}: {size} chars")


if __name__ == "__main__":
    main()
