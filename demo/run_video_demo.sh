#!/usr/bin/env bash
# Paced demo runner for video recording.
# Each scene clears the screen, prints a banner, runs the command, then
# pauses so OBS captures the result cleanly. Hit ENTER between scenes.
#
# Usage:
#   CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab \
#   bash demo/run_video_demo.sh
#
# Flags:
#   AUTO=1   advance scenes after AUTO_DELAY seconds (default 6) instead of ENTER
#   AUTO_DELAY=8  override delay when AUTO=1
#   SKIP_PROVIDERS=1  skip scenes that need API keys (4-7), useful for dry runs

set -uo pipefail

LAB_ROOT="${CYBERSEC_LAB:-$HOME/.hermes/workspace/cybersecurity-lab}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

AUTO="${AUTO:-0}"
AUTO_DELAY="${AUTO_DELAY:-6}"
SKIP_PROVIDERS="${SKIP_PROVIDERS:-0}"

# Colors (turn off with NO_COLOR=1)
if [[ -z "${NO_COLOR:-}" ]]; then
  C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'; C_RST=$'\e[0m'
  C_CYAN=$'\e[36m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
else
  C_DIM=""; C_BOLD=""; C_RST=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""
fi

scene() {
  local num="$1"; shift
  local title="$1"; shift
  clear
  printf "%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n" "$C_CYAN" "$C_RST"
  printf "%s┃%s Scene %s — %s%s\n" "$C_CYAN" "$C_BOLD" "$num" "$title" "$C_RST"
  printf "%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n" "$C_CYAN" "$C_RST"
  echo
}

caption() {
  printf "%s  %s%s\n\n" "$C_YELLOW" "$*" "$C_RST"
}

pause() {
  if [[ "$AUTO" == "1" ]]; then
    sleep "$AUTO_DELAY"
  else
    printf "\n%s[ENTER to continue]%s " "$C_DIM" "$C_RST"
    read -r _
  fi
}

run() {
  printf "%s$%s %s\n" "$C_GREEN" "$C_RST" "$*"
  eval "$@"
}

needs_providers() {
  if [[ "$SKIP_PROVIDERS" == "1" ]]; then
    caption "(skipped — SKIP_PROVIDERS=1)"
    return 1
  fi
  return 0
}

# ── Scene 1 ──────────────────────────────────────────────────────────
scene 1 "Title"
if command -v figlet >/dev/null 2>&1; then
  figlet -f slant "MR. Robot" 2>/dev/null || echo "MR. Robot Adversarial"
else
  echo "MR. Robot Adversarial"
fi
echo
echo "  Autonomous AI Cyber Defense — SANS FIND EVIL! Hackathon 2026"
pause

# ── Scene 2 ──────────────────────────────────────────────────────────
scene 2 "The problem"
caption "AI-driven adversaries breach in <8 minutes."
caption "Human analysts still alt-tab between tools."
caption "We close the gap: scan → triage → adversarial review → verdict, ~30s."
pause

# ── Scene 3 ──────────────────────────────────────────────────────────
scene 3 "Architecture"
caption "Three trust layers, two model families, one rule-based judge."
run "sed -n '20,68p' README.md"
pause

# ── Scene 4 ──────────────────────────────────────────────────────────
scene 4 "Health check"
caption "Providers, scanners, and audit DB report ready."
if needs_providers; then
  run "python agents/mr_robot/triage.py --health"
fi
pause

# ── Scene 5 ──────────────────────────────────────────────────────────
scene 5 "Malicious sample — Python bind shell"
caption "Expected verdict: MALICIOUS."
run "head -20 \"$LAB_ROOT/test-corpus/malicious/bind_shell.py\""
echo
if needs_providers; then
  caption "Pipeline: scanners → MR. Robot (Nemotron) → Falsifier (DeepSeek)"
  run "python triage_orchestrator.py \"$LAB_ROOT/test-corpus/malicious/bind_shell.py\" --provider deepseek 2>/dev/null | jq '{verdict: .final_verdict, rationale, propagator: ._meta.propagator_family, auditor: ._meta.auditor_family, kinship_lock_risk: ._meta.kinship_lock_risk}'"
fi
pause

# ── Scene 6 ──────────────────────────────────────────────────────────
scene 6 "Benign sample — Django view with parameterized ORM"
caption "Expected verdict: BENIGN. Framework-aware Falsifier should refute any FP."
run "cat benign_corpus/django_user_view.py"
echo
if needs_providers; then
  run "python triage_orchestrator.py benign_corpus/django_user_view.py 2>/dev/null | jq '{verdict: .final_verdict, rationale, auditor: ._meta.auditor_family}'"
fi
pause

# ── Scene 7 ──────────────────────────────────────────────────────────
scene 7 "Self-correction loop — obfuscated npm worm"
caption "Triage uncertain on first pass; Falsifier triggers a re-run."
run "head -25 \"$LAB_ROOT/test-corpus/malicious/mr_robot_npm_worm.js\""
echo
if needs_providers; then
  caption "Max 2 iterations (Shehata & Li 2026: more cycles with same family amplify error)."
  run "python triage_orchestrator.py \"$LAB_ROOT/test-corpus/malicious/mr_robot_npm_worm.js\" 2>/dev/null | jq '{verdict: .final_verdict, iterations: (.correction_history | length), history: [.correction_history[] | {iter: .iteration, status: .falsifier_status, auditor: .heterogeneity.auditor_family}]}'"
fi
pause

# ── Scene 8 ──────────────────────────────────────────────────────────
scene 8 "Accuracy report — 99 malicious + 19 benign"
caption "Recall 100%. FPR 15.8% — three FPs listed transparently in the report."
run "jq '{accuracy: .metrics.accuracy, precision: .metrics.precision, recall: .metrics.recall, f1: .metrics.f1, fpr: .metrics.fpr, confusion_matrix: .metrics.confusion_matrix}' docs/accuracy_report.json"
pause

# ── Scene 9 ──────────────────────────────────────────────────────────
scene 9 "Audit trail — SANS requirement #8"
caption "Every tool call logged. SQLite WAL, JSON-exportable."
if [[ -f logs/audit_trail.db ]]; then
  run "sqlite3 logs/audit_trail.db '.headers on' '.mode column' 'SELECT tool_name, verdict, confidence, duration_ms FROM executions ORDER BY id DESC LIMIT 5;'"
else
  caption "(no audit DB yet — run any scenario first to populate)"
fi
pause

# ── Scene 10 ─────────────────────────────────────────────────────────
scene 10 "Closing"
if command -v figlet >/dev/null 2>&1; then
  figlet -f small "thanks" 2>/dev/null || echo "thanks"
else
  echo "thanks"
fi
echo
echo "  Repo:  https://github.com/Grizaceo/mr-robot-adversarial"
echo "  Guide: docs/try_it_out.md"
echo "  License: MIT"
echo
pause

clear
echo "Demo complete."
