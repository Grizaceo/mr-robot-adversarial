# Video Preflight + OBS Setup

Run through this checklist **once** before recording. Most of the polish in a
hackathon demo video comes from boring preparation, not editing.

---

## 1. Environment

```bash
# Required env vars
export CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab
export NVIDIA_API_KEY=nvapi-...        # propagator
export OPENROUTER_API_KEY=sk-or-...     # falsifier (DeepSeek)
# Optional
export OLLAMA_API_KEY=...

# Sanity check — should print "ok" for each provider you have keys for
python agents/mr_robot/triage.py --health
```

If any provider shows an error, fix the key before recording. The video should
not show a broken health check.

## 2. Populate audit DB beforehand

Scene 9 reads from `logs/audit_trail.db`. Make sure it has rows:

```bash
# Run one sample so the DB has at least 5 rows
python triage_orchestrator.py \
  "$CYBERSEC_LAB/test-corpus/malicious/bind_shell.py" > /dev/null
```

## 3. Dry run with no API calls

Sanity-check the pacing without burning credits:

```bash
SKIP_PROVIDERS=1 bash demo/run_video_demo.sh
```

Each scene should clear the screen, print the banner, run the visible
commands, and wait for ENTER. If something looks crowded, edit the captions
in `demo/video_script.md` rather than the script.

## 4. Time-budget rehearsal

Now run with providers enabled and a stopwatch:

```bash
time bash demo/run_video_demo.sh
```

Target: under 5:00. If you're over, the cheapest cuts are:
- Scene 3 (Architecture) — reduce the `sed` range to `28,55`.
- Scene 8 (Metrics) — drop `f1` and `precision` from the `jq` projection.

---

## 5. Terminal appearance

The terminal is the entire video. Make it look good:

| Setting | Recommended |
|---|---|
| Font | JetBrains Mono / Fira Code / Cascadia Code, **18-20pt** |
| Colors | Dark background, high-contrast theme (Dracula / Nord / Solarized Dark) |
| Cursor | Block, non-blinking (less distracting on video) |
| Window size | 1920×1080 capture region → terminal at 1600×900-ish, leaves a margin for caption overlay |
| Padding | Add ~24px inner padding so text doesn't kiss the edge |
| Prompt | Shorten to just `$ ` for the recording — long prompts eat horizontal space |
| Shell history | `clear && history -c` before starting so up-arrow doesn't reveal anything |

```bash
# Minimal recording prompt (paste before recording, restore after)
export PS1='$ '
clear && history -c
```

---

## 6. OBS Studio scene setup

### Sources

| Source | Type | Notes |
|---|---|---|
| Terminal | Window Capture (or Screen Capture cropped) | Crop to terminal bounds |
| Caption text | Text (GDI+ / FreeType) | One text source you edit per scene, OR ten sources toggled |
| Title card | Image source | PNG with title, fades in for Scene 1 only |
| Closing card | Image source | PNG with repo URL for Scene 10 only |

### Scene list (one OBS scene per content scene = easy to retake)

1. `01-title` — title PNG only
2. `02-problem` — terminal + caption overlay
3. `03-architecture` — terminal only
4. `04-health` — terminal + caption
5. `05-malicious` — terminal + caption
6. `06-benign` — terminal + caption
7. `07-correction` — terminal + caption
8. `08-metrics` — terminal + caption
9. `09-audit` — terminal + caption
10. `10-closing` — closing PNG only

If editing scene-by-scene is heavy, use **one scene** with the terminal and
edit captions in post (DaVinci Resolve free tier handles this fine; the SRT
in `demo/video_captions.srt` is a starting point).

### Recording settings

| Setting | Value |
|---|---|
| Output mode | Advanced |
| Recording format | MKV (safe against crashes) → remux to MP4 after |
| Encoder | x264 (or NVENC if you have an NVIDIA GPU on Windows host) |
| Bitrate | CBR 8000 Kbps (1080p) |
| FPS | 30 |
| Resolution | 1920×1080 base + 1920×1080 output |
| Audio | Disable all sources — terminal-only with captions, no mic |

### Hotkeys to set up

| Action | Suggested key |
|---|---|
| Start/Stop Recording | `Ctrl+Shift+R` |
| Pause Recording | `Ctrl+Shift+P` |
| Switch Scene | `Ctrl+F1`..`Ctrl+F10` (one per scene) |

`Pause` is your best friend if you fumble — pause, fix, unpause, no re-record.

---

## 7. Recording workflow

1. **Resize windows.** Move OBS preview off-screen or to a second monitor.
2. **Test caption visibility.** Open `demo/video_script.md` on the second
   monitor so you can flip between scenes.
3. **Start OBS recording.** Wait 2s of black/blank to give yourself a clean
   trim point at the start.
4. **Run** `bash demo/run_video_demo.sh` in the captured terminal.
5. **Hit ENTER** between scenes deliberately — give each verdict ~2s to
   register before advancing.
6. **Stop recording** after Scene 10 finishes (`Demo complete.` line).

If you flub a scene: pause OBS, hit ENTER in the script to advance, then
go back during editing. Don't restart — the worst takes still beat the
fourth re-record's stale energy.

---

## 8. Post-production minimum viable edit

1. Open MKV in DaVinci Resolve / Kdenlive / Premiere.
2. Import `demo/video_captions.srt` as a subtitle track. Adjust timings to
   match your actual takes (they will drift from the script — that's normal).
3. **Top-and-tail trim**: cut the 2s lead-in and any trailing dead space.
4. **Title and closing cards**: 8s and 20s respectively, with a 0.3s fade.
5. **Export MP4** (H.264, 1080p, ~10 Mbps).
6. **Verify total length** ≤ 5:00 — SANS rejects over-long submissions.

---

## 9. Common pitfalls

- **Long prompt with full path** — eats horizontal space and reveals home dir.
  Use `PS1='$ '` for the recording.
- **Visible API keys in history or shell output** — `set +x`, `history -c`,
  and check that no command echoes `$OPENROUTER_API_KEY` literally.
- **YouTube/Twitter notification pings on screen** — close Slack, Discord,
  notifications panel, system tray badges.
- **Tab completion ghost text** — disable if your shell shows fish-style
  history suggestions.
- **Mouse cursor in the recording** — hide the mouse in OBS source settings
  if Window Capture catches it.
- **Wrong locale** — `LANG=en_US.UTF-8` so `jq` and Python don't print
  Spanish-locale numbers (e.g. `0,97` instead of `0.97`).

---

## 10. Submission checklist for the video file

- [ ] Length ≤ 5:00
- [ ] 1080p (1920×1080) MP4 / H.264
- [ ] Captions either burned-in OR provided as separate `.srt`
- [ ] Repo URL visible in closing card
- [ ] No API keys, no personal paths beyond `~/...`, no notifications visible
- [ ] Uploaded to YouTube (unlisted) or hosted somewhere stable; URL in
      `docs/submission_requirements.md`
