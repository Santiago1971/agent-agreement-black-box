#!/usr/bin/env python3
"""Validate every entry of a log against schema/record.schema.json (needs: pip install jsonschema)."""
import json, os, sys
import jsonschema
HERE = os.path.dirname(os.path.abspath(__file__))
schema = json.load(open(os.path.join(HERE, "..", "schema", "record.schema.json"), encoding="utf-8"))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "examples", "sample-log.json")
log = json.load(open(path, encoding="utf-8"))
for e in log:
    jsonschema.validate(e, schema)
print(f"schema OK for {len(log)} entries in {os.path.basename(path)}")
