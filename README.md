# FIND EVIL! — Autonomous Cyber Defense Agent System

**Hackathon:** FIND EVIL! AI threats strike in minutes  
**Deadline:** June 15, 2026  
**Team:** DAVI + Cristóbal  
**Status:** Blueprint ready for implementation  

## 🎯 Mission

Build an autonomous AI agent system that detects, analyzes, and responds to cybersecurity threats in real-time — using the mature `cybersecurity-lab` infrastructure already built.

## 🏗️ Architecture Overview

- **DefenderAgent**: Main orchestrator (receives alerts, coordinates response)
- **ThreatDetector**: Analyzes logs, YARA rules, Sigma patterns
- **ResponseOrchestrator**: Executes containment actions (isolate, block, alert)
- **CybersecLabAdapter**: Bridges to existing `~/.hermes/workspace/cybersecurity-lab/`

## 🚀 Quick Start (for implementer)

1. Clone this repo
2. Install dependencies: `pip install -r requirements.txt`
3. Configure `cybersec-lab-integration/config.yaml` with your lab path
4. Run demo: `./demo/run_demo.sh`
5. See submission instructions in `docs/submission_requirements.md`

## 📁 Structure

- `agents/` — Core agent implementations
- `cybersec-lab-integration/` — Adapters to existing lab
- `demo/` — Shooting script for 3-minute video
- `docs/` — Detailed architecture and requirements

## 🔗 Related Repositories

- `~/.hermes/workspace/cybersecurity-lab/` (existing, 67/67 Grade A scenarios)
- RepoCiv (optional for spatial orchestration)

---

**Blueprint prepared:** 2026-05-14 by DAVI  
**Handoff ready:** Yes — see HANDOFF.md
