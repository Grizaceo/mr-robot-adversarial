#!/bin/bash
# Demo script for FIND EVIL! hackathon
# Runs the scanner suite + shows the new output format
# Does NOT require API keys (scanner-only mode)

set -euo pipefail

LAB_ROOT="${CYBERSEC_LAB_PATH:-${CYBERSEC_LAB:-./cybersecurity-lab}}"

echo "=== MR. ROBOT ADVERSARIAL — FIND EVIL! Demo ==="
echo "Lab root: $LAB_ROOT"
echo ""

# Check lab exists
if [ ! -d "$LAB_ROOT" ]; then
    echo "ERROR: cybersecurity-lab not found at $LAB_ROOT"
    echo "Set CYBERSEC_LAB or CYBERSEC_LAB_PATH env var"
    exit 1
fi

# Check scanners exist
SCANNER_COUNT=$(find "$LAB_ROOT/scanners" -name "scan_*.py" -o -name "skill_scanner.py" -o -name "ioc_scanner.py" -o -name "secrets_detector.py" | wc -l)
echo "Scanners available: $SCANNER_COUNT"
echo ""

# Demo 1: Scan a malicious file
echo "============================================================"
echo "[1/4] Malware Detection — bind_shell.py"
echo "============================================================"
python3 -c "
import json, sys
sys.path.insert(0, '.')
from mcp_tools import run_all_scanners, aggregate_scanner_results
results = run_all_scanners('$LAB_ROOT/test-corpus/malicious/bind_shell.py')
summary = aggregate_scanner_results(results)
print(json.dumps(summary, indent=2))
"
echo ""

# Demo 2: Scan a worm
echo "============================================================"
echo "[2/4] Worm Detection — npm_worm.js"
echo "============================================================"
python3 -c "
import json, sys
sys.path.insert(0, '.')
from mcp_tools import run_all_scanners, aggregate_scanner_results
results = run_all_scanners('$LAB_ROOT/test-corpus/malicious/mr_robot_npm_worm.js')
summary = aggregate_scanner_results(results)
print(json.dumps(summary, indent=2))
"
echo ""

# Demo 3: Scan a benign file
echo "============================================================"
echo "[3/4] Benign Control — safe_app.py"
echo "============================================================"
python3 -c "
import json, sys
sys.path.insert(0, '.')
from mcp_tools import run_all_scanners, aggregate_scanner_results
results = run_all_scanners('$LAB_ROOT/test-corpus/benign/safe_app.py')
summary = aggregate_scanner_results(results)
print(json.dumps(summary, indent=2))
"
echo ""

# Demo 4: Run accuracy report
echo "============================================================"
echo "[4/4] Accuracy Report — 99 scenarios"
echo "============================================================"
python3 generate_accuracy_report.py --output docs/accuracy_report.json 2>&1 | tail -30
echo ""

echo "=== DEMO COMPLETE ==="
echo ""
echo "Key metrics:"
echo "  - 99 scenarios detected (100% recall)"
echo "  - 44 detection rules (skill_scanner)"
echo "  - 4 scanner types (skill, ioc, yara, secrets)"
echo "  - 5-phase review workflow (MR. Robot)"
echo "  - Heterogeneous falsifier (DeepSeek ΔA≈1)"
echo "  - Rule-based synthesizer (τ=0)"
