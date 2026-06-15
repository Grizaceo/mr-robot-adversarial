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
AUTO_DELAY="${AUTO_DELAY:-3}"
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
echo "  Autonomous AI Cyber Defense — SANS FIND EVIL! 2026"
pause

# ── Scene 2 ──────────────────────────────────────────────────────────
scene 2 "The problem"
caption "AI adversaries breach in <8 min. Humans still alt-tab."
caption "We close the gap: scan → triage → adversarial review → verdict, ~30s."
pause

# ── Scene 3 ──────────────────────────────────────────────────────────
scene 3 "Architecture"
caption "Three trust layers, two model families, one rule-based judge."
run "sed -n '20,50p' README.md"
pause

# ── Scene 4 ──────────────────────────────────────────────────────────
scene 4 "Health check"
caption "Providers, scanners, audit DB ready."
if needs_providers; then
  run "python agents/mr_robot/triage.py --health"
fi
pause

# ── Scene 5 ──────────────────────────────────────────────────────────
scene 5 "Malicious sample — Python bind shell"
caption "Expected: MALICIOUS."
run "head -15 \"$LAB_ROOT/test-corpus/malicious/bind_shell.py\""
echo
if needs_providers; then
  caption "Pipeline: scanners → MR. Robot → Falsifier → Synthesizer"
  run "python triage_orchestrator.py \"$LAB_ROOT/test-corpus/malicious/bind_shell.py\" 2>/dev/null | jq '{verdict: .final_verdict, rationale, propagator: ._meta.propagator_family, auditor: ._meta.auditor_family, kinship_lock_risk: ._meta.kinship_lock_risk}'"
fi
pause

# ── Scene 6 ──────────────────────────────────────────────────────────
scene 6 "Benign sample — Django view with parameterized ORM"
caption "Expected: BENIGN. Falsifier refutes FPs."
run "cat benign_corpus/django_user_view.py"
echo
if needs_providers; then
  run "python triage_orchestrator.py benign_corpus/django_user_view.py 2>/dev/null | jq '{verdict: .final_verdict, rationale, auditor: ._meta.auditor_family}'"
fi
pause

# ── Scene 7 ──────────────────────────────────────────────────────────
scene 7 "Self-correction sequence — a real verdict flip (BENIGN → SUSPICIOUS)"
caption "Django view. First-pass triage (gpt-oss) → BENIGN. We force the heterogeneous review."
caption "Falsifier (nemotron-3-ultra, ΔA=1.0) FALSIFIES it → MR. Robot re-runs → escalates."
run "head -15 benign_corpus/django_user_view.py"
echo
if needs_providers; then
  caption "Note: 4 live LLM calls (~4-5 min). The flip is reproducible on real providers."
  run "MR_ROBOT_FORCE_FALSIFIER=1 python triage_orchestrator.py benign_corpus/django_user_view.py 2>/dev/null | jq '{final: .final_verdict, history: [.correction_history[] | {iter: .iteration, status: .falsifier_status, auditor: .heterogeneity.auditor_family, dist: .heterogeneity.architectural_distance}]}'"
  caption "The correction is recorded in the audit trail, not narrated:"
  run "python triage_orchestrator.py --last 2>/dev/null | jq '.steps[] | select(.tool==\"self_correction\") | .output'"
fi
pause

# ── Scene 8 ──────────────────────────────────────────────────────────
scene 8 "Accuracy report — 173 samples (135 malicious + 38 benign)"
caption "Recall 100% (no missed malicious). Precision 99.26%. FPR 2.63% (1 FP)."
run "jq '{accuracy: .metrics.accuracy, precision: .metrics.precision, recall: .metrics.recall, f1: .metrics.f1, fpr: .metrics.fpr, confusion_matrix: .metrics.confusion_matrix}' docs/accuracy_report.json"
pause

# ── Scene 9 ──────────────────────────────────────────────────────────
scene 9 "Audit trail — SANS requirement #8"
caption "Every tool call logged. SQLite WAL, JSON-exportable, with timestamps."
if [[ -f logs/audit_trail.db ]]; then
  run "sqlite3 logs/audit_trail.db '.headers on' '.mode column' 'SELECT tool_name, verdict, confidence, duration_ms, created_at FROM executions WHERE verdict IS NOT NULL ORDER BY id DESC LIMIT 5;'"
else
  caption "(run a scenario first to populate)"
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
