# HANDOFF — Implementation Guide

## 🎯 Objective

Implement the MR. Robot Adversarial submission according to BLUEPRINT.md.

## 🚦 Get Started

1. Read `BLUEPRINT.md` completely
2. Ensure `~/.hermes/workspace/cybersecurity-lab/` exists and is functional (67/67 Grade A)
3. Create virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Implement agents in `agents/` following the interface contracts in `docs/architecture.md`
6. Implement adapter in `cybersec-lab-integration/`
7. Write demo scenarios in `demo/scenarios/`
8. Create `docs/architecture.md` with system diagram
9. Test end-to-end with `./demo/run_demo.sh`
10. Record video (≤3 min) showing all 3 scenarios
11. Submit via Devpost

## 📦 Dependencies

- Python 3.11+
- `requests`, `pydantic`, `pyyaml` (see requirements.txt)
- Access to LLM API or local model (DeepSeek/Claude/Gemini)
- Existing cybersecurity-lab (no changes to core)

## 🧪 Testing

- Unit tests in `tests/` (pytest)
- Integration test: agent detects real YARA match from lab
- Demo must be reproducible on fresh clone

## 📸 Demo Requirements

- 3 minutes maximum
- Show actual cybersecurity-lab output (real logs)
- Show agent decision-making (LLM reasoning traces)
- Show automated response actions
- Narrate what's happening (voiceover acceptable)

## ⚠️ Constraints

- Do NOT modify cybersecurity-lab core code
- Do NOT use fake/mock data in final demo (lab has real scenarios)
- Keep licenses MIT/OSI-approved
- Repository must be public on GitHub

## 🤝 Support

If blocked, refer to `docs/architecture.md` for design decisions.
For questions about the lab, check `~/.hermes/workspace/cybersecurity-lab/README.md`.

---

**Blueprint version:** 0.2.0-blueprint  
**Prepared by:** Cristóbal (vía modelar skill)  
**Date:** 2026-05-14
