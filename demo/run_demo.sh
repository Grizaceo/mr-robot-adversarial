#!/bin/bash
set -euo pipefail

LAB_ROOT="${CYBERSEC_LAB_PATH:-${CYBERSEC_LAB:-./cybersecurity-lab}}"

run_case() {
  local label="$1"
  local target="$2"
  echo "============================================================"
  echo "$label"
  echo "FILE: $target"
  echo "------------------------------------------------------------"
  python - <<'PY' "$target"
import json
import sys
from triage_falsifier import run_self_correction_loop

path = sys.argv[1]
report = run_self_correction_loop(path, confidence_threshold=0.7, max_iterations=1)
print(json.dumps(report, indent=2, default=str))
PY
  echo
}

echo "=== MR. ROBOT ADVERSARIAL DEMO ==="
echo "Lab root: $LAB_ROOT"
echo

run_case "[1/3] Malware Detection" "$LAB_ROOT/test-corpus/malicious/bind_shell.py"
run_case "[2/3] Worm / Adversarial JS" "$LAB_ROOT/test-corpus/malicious/mr_robot_npm_worm.js"
run_case "[3/3] Benign Control" "$LAB_ROOT/test-corpus/benign/safe_app.py"

echo "=== DEMO COMPLETE ==="
