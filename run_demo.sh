#!/usr/bin/env sh
# One command: build the sample log, verify it, run the tamper tests, check the schema.
set -e
cd "$(dirname "$0")"
python3 tools/aabb.py demo
echo
echo "--- CLI verify: original ---"
python3 tools/aabb.py verify examples/sample-log.json
echo "--- CLI verify: tampered (expected to fail) ---"
if python3 tools/aabb.py verify examples/sample-log-tampered.json; then
  echo "ERROR: tampering was not detected"; exit 1
else
  echo "(exit 1 as expected)"
fi
if python3 -c "import jsonschema" 2>/dev/null; then
  echo "--- schema ---"; python3 tools/check_schema.py
fi
