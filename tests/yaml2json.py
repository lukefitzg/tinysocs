#!/usr/bin/env python3
"""Convert a YAML file to JSON on stdout.

Used by Test-AtomicDetection.ps1 as a fallback when the
powershell-yaml module is unavailable.
"""
import json
import sys

import yaml

if len(sys.argv) < 2:
    print("Usage: python yaml2json.py <file.yaml>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1], encoding="utf-8") as f:
    data = yaml.safe_load(f)

print(json.dumps(data))
