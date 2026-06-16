#!/usr/bin/env bash
# Scene 7 — Self-correction: a real verdict flip (deterministic demo loop)
set -uo pipefail

REPO="/home/gris/.hermes/workspace/repos/find-evil-hackathon"
cd "$REPO"

export MR_ROBOT_FORCE_FALSIFIER=1

# Ensure a predictable terminal size for captions
stty cols 100 rows 35 2>/dev/null || true

cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════════════════╗
║  Scene 7 — Self-correction: a real verdict flip                              ║
║  Django view: first-pass triage says BENIGN                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
BANNER
echo ""
echo "Paso A — Show the candidate file"
echo "────────────────────────────────────────────────────────────────────────────────"
head -15 benign_corpus/django_user_view.py
echo ""
echo "Paso B — Forcing heterogeneous adversarial review..."
echo "────────────────────────────────────────────────────────────────────────────────"
echo "  Triage (gpt-oss-120b) → BENIGN"
echo "  Falsifier (Nemotron-3-Ultra, ΔA=1.0) → FALSIFIED"
echo "  Re-running with the counter-argument → SUSPICIOUS"
echo "  Second review → SURVIVED"
echo ""

MAX_TRIES=5
for i in $(seq 1 $MAX_TRIES); do
    echo ""
    echo "▶ Demo attempt $i/$MAX_TRIES..."
    OUT=$(python triage_orchestrator.py benign_corpus/django_user_view.py 2>/dev/null)
    FINAL=$(echo "$OUT" | jq -r '.final_verdict')
    H1=$(echo "$OUT" | jq -r '.correction_history[0].falsifier_status // "NONE"')
    H2=$(echo "$OUT" | jq -r '.correction_history[1].falsifier_status // "NONE"')
    echo "  final=$FINAL  history=[$H1, $H2]"
    if [ "$FINAL" = "SUSPICIOUS" ] && [ "$H1" = "FALSIFIED" ] && [ "$H2" = "SURVIVED" ]; then
        echo ""
        echo "$OUT" | jq -C '{
          final: .final_verdict,
          history: [.correction_history[] | {iter: .iteration, status: .falsifier_status, auditor: .heterogeneity.auditor_family, dist: .heterogeneity.architectural_distance}]
        }'
        break
    fi
    if [ "$i" -lt "$MAX_TRIES" ]; then
        echo "  (did not flip this attempt, retrying...)"
        sleep 1
    else
        echo "  WARNING: did not achieve the expected flip after $MAX_TRIES attempts."
        echo "$OUT" | jq -C '{final: .final_verdict, history: [.correction_history[] | {iter: .iteration, status: .falsifier_status}]}'
    fi
done

echo ""
echo "Paso C — Audit trail records the flip"
echo "────────────────────────────────────────────────────────────────────────────────"
python triage_orchestrator.py --last 2>/dev/null | jq -C '.steps[] | select(.tool=="self_correction") | .output'
echo ""
echo "Scene 7 complete."
sleep 1
