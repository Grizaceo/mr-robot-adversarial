# Demo Assets for MR. Robot Adversarial

This directory contains everything you need to (a) showcase the pipeline
locally and (b) record the SANS submission video.

## Video assets (≤5 min, terminal-only with captions)

| File | Purpose |
|---|---|
| [`video_script.md`](video_script.md) | Scene-by-scene guion in English: 10 scenes, 5:00 total, with exact commands and on-screen captions |
| [`video_preflight.md`](video_preflight.md) | Preflight checklist + OBS Studio scene setup + post-production minimum viable edit |
| [`video_captions.srt`](video_captions.srt) | Subtitle track in SRT format — drop into DaVinci Resolve / Kdenlive / Premiere |
| [`run_video_demo.sh`](run_video_demo.sh) | Paced shell driver: clears screen and pauses between scenes so OBS captures consistent timing |

### Quickstart for the recording

```bash
export CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab
export NVIDIA_API_KEY=nvapi-...
export OPENROUTER_API_KEY=sk-or-...

# Dry-run with no API calls to validate pacing
SKIP_PROVIDERS=1 bash demo/run_video_demo.sh

# Real run during OBS recording (hit ENTER between scenes)
bash demo/run_video_demo.sh
```

See [`video_preflight.md`](video_preflight.md) for the full setup checklist
(terminal font/size, OBS encoder, hotkeys, common pitfalls).

## Local demo (no recording, no API keys)

| File | Purpose |
|---|---|
| [`run_demo.sh`](run_demo.sh) | Full pipeline on three samples (malware, worm, benign control), needs API keys |
| [`run_demo_local.sh`](run_demo_local.sh) | Scanner-only demo, no LLM calls |
| [`scenarios/`](scenarios/) | Scenario YAML/JSON fixtures used by the local demos |

```bash
# No API keys needed — pure deterministic scanners
CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab \
  bash demo/run_demo_local.sh
```

## What the video shows

1. Title card
2. Problem statement (8-minute breach time)
3. Architecture (three trust layers, two model families, rule-based judge)
4. Health check
5. Malicious sample — Python bind shell → MALICIOUS
6. Benign sample — Django view with parameterized ORM → BENIGN (no FP)
7. Self-correction loop — npm worm where the Falsifier triggers a re-run
8. Accuracy report on 118 ground-truth samples (real precision, real FPR)
9. Audit trail query (SANS requirement #8)
10. Closing card

Total: 5:00 with ~10-15s of slack budget.
