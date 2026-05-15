# Demo Scenarios for MR. Robot Adversarial

This directory contains the shooting script and scenario definitions for the 3-minute demo video.

## 🎬 Shooting Script

### Scene 1: Malware Detection & Auto-Response (0:30–1:30)
- Setup: A malicious executable drops in the lab's test corpus
- YARA rule `malware_baby.exe` triggers
- DefenderAgent receives alert, ThreatDetector analyzes
- ResponseOrchestrator isolates the host (file quarantine)
- Result: Scoreboard updates, threat contained

**Show:** YARA match log → Agent processing → Quarantine action → Scoreboard

### Scene 2: APT Simulation (1:30–2:30)
- Setup: Multi-stage attack chain (recon → exploit → C2)
- Sigma rules detect lateral movement
- ThreatDetector correlates multiple alerts into single incident
- ResponseOrchestrator blocks attacker IP at firewall
- Result: Attack chain broken, alert sent to human

**Show:** Sigma alerts correlation → IP block → Timeline view

### Scene 3: Zero-Day Adaptation (2:30–2:50)
- Setup: Novel attack pattern not covered by existing rules
- System anomaly detection triggers generic alert
- DefenderAgent uses LLM to hypothesize threat vector
- Creates temporary detection rule (human-in-the-loop approval simulated)
- Result: New threat caught before widespread impact

**Show:** LLM reasoning traces → Proposed rule → Approved & deployed → Detection confirmed

## 📹 Recording Tips

- Use `asciinema` or `SimpleScreenRecorder` for terminal
- Show real terminal, not slides
- Narrate with voiceover (or subtitles)
- Keep each scene under 40 seconds
- Total duration: 2:45–3:00

## 🚀 Run the Full Demo

```bash
./demo/run_demo.sh
```

This script executes all three scenarios sequentially and prints timestamps for editing.
