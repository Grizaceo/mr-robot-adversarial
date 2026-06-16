#!/usr/bin/env python3
"""Regenerate demo/video_captions.srt to match the v3 video (3:10, 173 samples, 1 FP)."""
from pathlib import Path

# Per-scene subtitles matching demo/demo_run_v3.mp4.
# Scene start/end times are derived from scripts/render_demo_video_v3.py.
SCENES = [
    (0.0, 8.0, "MR. Robot Adversarial — SANS FIND EVIL! 2026\nAutonomous AI cyber-defense pipeline."),
    (8.0, 22.0, "The problem: AI adversaries move in minutes.\nWe close the gap: scan → triage → adversarial review → verdict, ~30s."),
    (22.0, 40.0, "Three trust layers, two model families, one rule-based judge.\nScanners are deterministic; the auditor is a different model family."),
    (40.0, 60.0, "Health and quality gate: providers, scanners, audit DB.\nThe submitted tree passes 181 tests, with 4 skipped."),
    (60.0, 96.0, "Sample 1: Python bind shell. Expected verdict: MALICIOUS.\nC2 URL, socket bind, and subprocess loop are visible evidence."),
    (96.0, 128.0, "Sample 2: Django view with parameterized ORM. Expected verdict: BENIGN.\nFramework-aware review avoids a false alarm."),
    (128.0, 166.0, "Self-correction evidence from SQLite.\nFirst verdict BENIGN → heterogeneous review → SUSPICIOUS, flipped=true, ΔA=1.0."),
    (166.0, 178.0, "Accuracy on 173 samples: 135 malicious + 38 benign.\nAccuracy 99.42%, Precision 99.26%, Recall 100%, FPR 2.63%."),
    (178.0, 185.5, "Audit trail: every decision stage writes structured evidence.\nTool, verdict, confidence, and timestamp are reconstructable."),
    (185.5, 190.5, "Repo: github.com/Grizaceo/mr-robot-adversarial\nVideo: demo/demo_run_v3.mp4  •  License: MIT"),
]


def fmt_time(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int((seconds - int(seconds)) * 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def main():
    out = Path("demo/video_captions.srt")
    out.parent.mkdir(exist_ok=True)
    parts = []
    for i, (start, end, text) in enumerate(SCENES, 1):
        parts.append(f"{i}\n{fmt_time(start)} --> {fmt_time(end)}\n{text}\n")
    out.write_text("\n".join(parts))
    print(f"Wrote {out} ({len(SCENES)} cues, total {SCENES[-1][1]:.0f}s)")
    print(f"Last scene ends at {fmt_time(SCENES[-1][1])}")


if __name__ == "__main__":
    main()
