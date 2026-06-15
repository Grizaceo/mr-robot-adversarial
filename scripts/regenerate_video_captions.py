#!/usr/bin/env python3
"""Regenerate demo/video_captions.srt to match the v3 video (3:10, 173 samples, 1 FP)."""
from pathlib import Path

# Per-scene subtitles matching the v3 video render.
# Each scene is held for ~1.5s title + reveals + ~3s final.
# Scene start/end times are derived from the actual rendered video.
SCENES = [
    (0.0, 4.0, "MR. Robot Adversarial — SANS FIND EVIL! 2026\nAutonomous AI cyber-defense pipeline."),
    (4.0, 10.0, "The problem: AI adversaries breach in under 8 minutes.\nWe close the gap: scan → triage → adversarial review → verdict, ~30s."),
    (10.0, 24.0, "Three trust layers, two model families, one rule-based judge.\n(scanners deterministic, auditor different family from triage)"),
    (24.0, 37.0, "Health check — providers, scanners, audit DB online.\n4 wired scanners: skill, ioc, yara, secrets."),
    (37.0, 82.0, "Sample 1: Python bind shell. We expect MALICIOUS.\nPipeline: scanners (10 findings) → MR. Robot (gpt-oss) → synthesizer → MALICIOUS 0.97."),
    (82.0, 125.0, "Sample 2: Django view with parameterized ORM. We expect BENIGN.\nFalsifier refutes FPs. Final verdict: BENIGN 0.99."),
    (125.0, 176.0, "Sample 7: Self-correction loop. Forced with MR_ROBOT_FORCE_FALSIFIER=1.\nTriage (gpt-oss-120b) → MALICIOUS 0.97 → Falsifier (nemotron-3-ultra) → SURVIVED → ΔA=1.0, kinship_lock_risk=LOW."),
    (176.0, 188.0, "Sample 8: Accuracy on 173 samples (135 malicious + 38 benign).\nAccuracy 99.42%, Precision 99.26%, Recall 100%, FPR 2.63% (1 FP)."),
    (188.0, 195.0, "Sample 9: Audit trail — every tool call logged in SQLite with timestamps.\nSANS Requirement #8 satisfied."),
    (195.0, 200.0, "Repo: github.com/Grizaceo/mr-robot-adversarial\nLicense: MIT  •  Branch: grounding-audit-competition-pass"),
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
