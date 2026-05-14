# Submission Requirements — FIND EVIL! Hackathon

## 📦 Required Artifacts

1. **Public GitHub repository** (this repo)
2. **Demo video** ≤ 3 minutes, uploaded to YouTube or Vimeo (public)
3. **Text description** (README + this document)
4. **Architecture diagram** (in `docs/architecture.md`)
5. **Working code** that can be installed and run

## 🎬 Video Content (3 min max)

**Structure suggested:**
- 0:00–0:30 — Introduction: "What we built and why"
- 0:30–1:30 — Scenario 1: Malware detection + auto-containment
- 1:30–2:30 — Scenario 2: APT chain correlation + blocking
- 2:30–2:50 — Scenario 3: Zero-day adaptation + human-in-the-loop
- 2:50–3:00 — Impact summary: "Reduced MTTR from hours to seconds"

**Must show:**
- Actual cybersecurity-lab output (real logs, not fake)
- Agent reasoning (print LLM prompts/responses)
- Automated actions taken (quarantine files, block IPs)
- Final status update (scoreboard improvement)

## 📄 Text Description (README)

Should include:
- Problem statement
- System architecture (high-level)
- How to install and run (5-step max)
- How it integrates with existing cybersecurity-lab
- Technologies used (Python, LLM provider, libraries)

## 🏛️ Architecture Diagram

Include in `docs/architecture.md`:
- Component boxes (DefenderAgent, ThreatDetector, etc.)
- Data flow arrows
- External systems (cybersecurity-lab, LLM API)
- Keep it simple — draw.io or Mermaid acceptable

## ⚙️ Installation & Testing

Provide clear instructions:
```bash
git clone <repo>
cd find-evil-hackathon
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Edit config.yaml with your LLM API key and lab path
./demo/run_demo.sh
```

**Important:** The demo script should run the full 3-scenario demonstration end-to-end without manual intervention.

## 🧾 Judging Criteria (self-evaluation)

| Criterion | How we meet it |
|-----------|----------------|
| Completion & on-time | Fully functional agent, submitted before deadline |
| Build self-improving agents | LLM-based analysis improves with more data (retrieval from lab history) |
| Real-world impact | Reduces manual triage time dramatically |
| Demo clarity | 3-min video shows clear before/after |

## 📅 Timeline

- Blueprint prepared: 2026-05-14
- Implementation: 2–3 days
- Testing & demo recording: 1 day
- Submission: June 15, 2026 (before deadline)

---

**Handoff ready for implementation agent.**
