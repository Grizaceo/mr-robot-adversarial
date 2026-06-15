# Dataset Documentation — MR. Robot Adversarial

## Overview

The MR. Robot Adversarial evaluation corpus consists of **135 adversarial malicious
scenarios** and **38 benign samples** (12 in this repo's `benign_corpus/` +
26 in `cybersecurity-lab/test-corpus/benign/`), for a total of **173 ground-truth
labelled samples** used to measure both recall and false-positive rate.

**Sources:**
- Malicious: `cybersecurity-lab/test-corpus/malicious/` (lab total: 140 files; evaluation subset: 135 scannable)
- Benign: `benign_corpus/` (this repo, 12 samples) + `cybersecurity-lab/test-corpus/benign/` (26 samples)

**Format:** Raw source files (Python, JS, YAML, shell, etc.) — what a real IR responder would encounter
**License:** MIT (same as repository)

## Headline Metrics (from `docs/accuracy_report.json`)

| Metric | Value |
|--------|-------|
| Total samples | 173 |
| True positives (malicious correctly flagged) | 135 |
| False positives (benign flagged) | 1 |
| True negatives (benign correctly cleared) | 37 |
| False negatives (malicious missed) | 0 |
| **Accuracy** | **99.42%** |
| **Precision** | **99.26%** |
| **Recall** | **100.00%** |
| **F1** | **99.63%** |
| **FPR (False Positive Rate)** | **2.63%** (1/38 benigns flagged) |

## Severity Distribution (per-severity recall)

| Severity | Total | Recall |
|----------|-------|--------|
| Critical | 66 | 100% (66/66) |
| High | 62 | 100% (62/62) |
| Medium | 7 | 100% (7/7) |
| None | 38 | 0% (0/38) |

## Per-Detector Performance

| Detector | Detected / Total | Recall | Status |
|----------|------------------|--------|--------|
| `yara` | 125/125 | 100.0% | wired |
| `skill_scanner` | 96/97 | 99.0% | wired |
| `ioc_scanner` | 108/110 | 98.2% | wired |
| `secrets_detector` | 11/12 | 91.7% | wired |
| `behavioral_monitor` | 0/4 | 0.0% | **not wired** |
| `drift` | 0/71 | 0.0% | **not wired** (no implementation) |
| `sigma` | 0/32 | 0.0% | **not wired** (scenario-labelled, no scanner in pipeline) |
| `suricata` | 0/3 | 0.0% | **not wired** |

> Only 4 of the 8 scenario-expected detector *labels* correspond to scanners that
> actually run (`yara`, `skill_scanner`, `ioc_scanner`, `secrets_detector`). The
> other 4 are ground-truth labels from the scenario corpus with no backing scanner
> in this pipeline — their 0% is structural, not a missed detection. Overall recall
> is still 100% because every malicious sample is caught by at least one wired scanner.

## Attack Category Distribution (per-tag recall)

| Tag | Total | Detected | Recall |
|-----|-------|----------|--------|
| `benign` | 38 | 0 | 0% |
| `supply-chain` | 37 | 37 | 100% |
| `exfiltration` | 25 | 25 | 100% |
| `c2` | 22 | 22 | 100% |
| `adversarial` | 18 | 18 | 100% |
| `llm-generated` | 18 | 18 | 100% |
| `credential-theft` | 14 | 14 | 100% |
| `agentic-ai` | 14 | 14 | 100% |
| `atlas-2026` | 14 | 14 | 100% |
| `defense-evasion` | 12 | 12 | 100% |
| `persistence` | 11 | 11 | 100% |
| `web-attack` | 9 | 9 | 100% |
| `container` | 8 | 8 | 100% |
| `ci-cd` | 8 | 8 | 100% |
| `cloud` | 7 | 7 | 100% |
| `lolbin` | 7 | 7 | 100% |
| `injection` | 7 | 7 | 100% |
| `kubernetes` | 6 | 6 | 100% |
| `fileless` | 6 | 6 | 100% |
| `container-security` | 5 | 5 | 100% |
| `social-engineering` | 5 | 5 | 100% |
| `malware` | 5 | 5 | 100% |
| `ai-security` | 4 | 4 | 100% |
| `container-escape` | 4 | 4 | 100% |
| `ai-native` | 4 | 4 | 100% |
| `phishing` | 4 | 4 | 100% |
| `github-actions` | 4 | 4 | 100% |
| `powershell` | 4 | 4 | 100% |
| `ai-ml` | 3 | 3 | 100% |
| `privilege-escalation` | 3 | 3 | 100% |
| `prompt-injection` | 3 | 3 | 100% |
| `mcp` | 3 | 3 | 100% |
| `obfuscation` | 3 | 3 | 100% |
| `wasm` | 2 | 2 | 100% |
| `npm` | 2 | 2 | 100% |
| `claude-code` | 2 | 2 | 100% |
| `dragos-2026` | 2 | 2 | 100% |
| `polymorphic` | 2 | 2 | 100% |
| `backdoor` | 2 | 2 | 100% |
| `lateral-movement` | 2 | 2 | 100% |
| `mimikatz` | 2 | 2 | 100% |
| `active-directory` | 2 | 2 | 100% |
| `credential-dumping` | 2 | 2 | 100% |
| `wmi` | 2 | 2 | 100% |
| `token-theft` | 2 | 2 | 100% |
| `kerberos` | 2 | 2 | 100% |
| `scripting` | 2 | 2 | 100% |
| `windows` | 2 | 2 | 100% |
| `autonomous-agents` | 1 | 1 | 100% |
| `rlhf-bypass` | 1 | 1 | 100% |
| `model-security` | 1 | 1 | 100% |
| `zero-trust` | 1 | 1 | 100% |
| `keyvault` | 1 | 1 | 100% |
| `ai-accelerated` | 1 | 1 | 100% |
| `account-takeover` | 1 | 1 | 100% |
| `vercel-pattern-2026` | 1 | 1 | 100% |
| `ai-platform-breach` | 1 | 1 | 100% |
| `tool-hijack` | 1 | 1 | 100% |
| `agent-security` | 1 | 1 | 100% |
| `indirect-injection` | 1 | 1 | 100% |
| `deepfake` | 1 | 1 | 100% |
| `vishing` | 1 | 1 | 100% |
| `ai-social-engineering` | 1 | 1 | 100% |
| `ai-discovered` | 1 | 1 | 100% |
| `zero-day` | 1 | 1 | 100% |
| `autonomous-exploit` | 1 | 1 | 100% |
| `gtig-2026` | 1 | 1 | 100% |
| `state-actor` | 1 | 1 | 100% |
| `vulnerability-discovery` | 1 | 1 | 100% |
| `in-the-wild` | 1 | 1 | 100% |
| `llm-as-attacker` | 1 | 1 | 100% |
| `exploitation-framework` | 1 | 1 | 100% |
| `mexico-campaign` | 1 | 1 | 100% |
| `gambit-2026` | 1 | 1 | 100% |
| `ai-orchestration` | 1 | 1 | 100% |
| `llm-malware` | 1 | 1 | 100% |
| `zero-signature` | 1 | 1 | 100% |
| `t1648` | 1 | 1 | 100% |
| `dropper` | 1 | 1 | 100% |
| `llm-evasion` | 1 | 1 | 100% |
| `memory-poisoning` | 1 | 1 | 100% |
| `rag` | 1 | 1 | 100% |
| `pth` | 1 | 1 | 100% |
| `litellm-class` | 1 | 1 | 100% |
| `lora` | 1 | 1 | 100% |
| `training-data-poisoning` | 1 | 1 | 100% |
| `memory` | 1 | 1 | 100% |
| `owasp-llm-02` | 1 | 1 | 100% |
| `depth-analysis` | 1 | 1 | 100% |
| `tool-use` | 1 | 1 | 100% |
| `jailbreaking` | 1 | 1 | 100% |
| `self-evolving` | 1 | 1 | 100% |
| `multi-stage` | 1 | 1 | 100% |
| `bec` | 1 | 1 | 100% |
| `email` | 1 | 1 | 100% |
| `cicd-worm` | 1 | 1 | 100% |
| `self-propagating` | 1 | 1 | 100% |
| `pat-abuse` | 1 | 1 | 100% |
| `source-leak` | 1 | 1 | 100% |
| `mcp-abuse` | 1 | 1 | 100% |
| `kernel-module` | 1 | 1 | 100% |
| `rootkit` | 1 | 1 | 100% |
| `lkm` | 1 | 1 | 100% |
| `nsenter` | 1 | 1 | 100% |
| `docker` | 1 | 1 | 100% |
| `docker-socket` | 1 | 1 | 100% |
| `privileged` | 1 | 1 | 100% |
| `pod-escape` | 1 | 1 | 100% |
| `dcom` | 1 | 1 | 100% |
| `mmc20` | 1 | 1 | 100% |
| `cobalt-strike` | 1 | 1 | 100% |
| `dcsync` | 1 | 1 | 100% |
| `domain-controller` | 1 | 1 | 100% |
| `ntlm` | 1 | 1 | 100% |
| `dmarc` | 1 | 1 | 100% |
| `spoofing` | 1 | 1 | 100% |
| `ransomware` | 1 | 1 | 100% |
| `encryptionless` | 1 | 1 | 100% |
| `destructive` | 1 | 1 | 100% |
| `extortion` | 1 | 1 | 100% |
| `golden-ticket` | 1 | 1 | 100% |
| `krbtgt` | 1 | 1 | 100% |
| `domain-admin` | 1 | 1 | 100% |
| `forgery` | 1 | 1 | 100% |
| `kerberoasting` | 1 | 1 | 100% |
| `impacket` | 1 | 1 | 100% |
| `credential-access` | 1 | 1 | 100% |
| `tgs` | 1 | 1 | 100% |
| `certutil` | 1 | 1 | 100% |
| `mshta` | 1 | 1 | 100% |
| `bypass` | 1 | 1 | 100% |
| `msiexec` | 1 | 1 | 100% |
| `silent-install` | 1 | 1 | 100% |
| `regsvr32` | 1 | 1 | 100% |
| `com-scriptlet` | 1 | 1 | 100% |
| `squiblydoo` | 1 | 1 | 100% |
| `rundll32` | 1 | 1 | 100% |
| `wmic` | 1 | 1 | 100% |
| `process-creation` | 1 | 1 | 100% |
| `lsass` | 1 | 1 | 100% |
| `minidump` | 1 | 1 | 100% |
| `ot` | 1 | 1 | 100% |
| `ics` | 1 | 1 | 100% |
| `scada` | 1 | 1 | 100% |
| `gateway` | 1 | 1 | 100% |
| `vnode` | 1 | 1 | 100% |
| `password-spraying` | 1 | 1 | 100% |
| `it-ot-pivot` | 1 | 1 | 100% |
| `ai-driven` | 1 | 1 | 100% |
| `claude-code-campaign` | 1 | 1 | 100% |
| `credential-harvesting` | 1 | 1 | 100% |
| `process-hollowing` | 1 | 1 | 100% |
| `process-injection` | 1 | 1 | 100% |
| `svchost` | 1 | 1 | 100% |
| `shellcode` | 1 | 1 | 100% |
| `llm` | 1 | 1 | 100% |
| `registry` | 1 | 1 | 100% |
| `run-keys` | 1 | 1 | 100% |
| `winlogon` | 1 | 1 | 100% |
| `ifeo` | 1 | 1 | 100% |
| `scheduled-task` | 1 | 1 | 100% |
| `spearphishing` | 1 | 1 | 100% |
| `macro` | 1 | 1 | 100% |
| `vba` | 1 | 1 | 100% |
| `postinstall` | 1 | 1 | 100% |
| `pipeline` | 1 | 1 | 100% |
| `trust-dialog` | 1 | 1 | 100% |
| `trustfall-class` | 1 | 1 | 100% |
| `nhi` | 1 | 1 | 100% |
| `github` | 1 | 1 | 100% |
| `worm` | 1 | 1 | 100% |
| `dead-mans-switch` | 1 | 1 | 100% |
| `shyhaldane-2026` | 1 | 1 | 100% |
| `github-token-theft` | 1 | 1 | 100% |
| `autonomous-payload` | 1 | 1 | 100% |
| `tag-poisoning` | 1 | 1 | 100% |
| `cicd` | 1 | 1 | 100% |
| `teampcp` | 1 | 1 | 100% |
| `event-subscription` | 1 | 1 | 100% |
| `apt` | 1 | 1 | 100% |

## The 1 False Positive

The single FP is on a benign corpus sample flagged by `secrets_detector`. Documented
in `docs/accuracy_report.json` as a known FP, with a fix in the scanner rule queued.

## Limitations — Read Before Citing

- **Self-authored corpus.** Recall=100% reflects curated corpus bias, not
  generalization to novel attacks. We document this honestly rather than claim
  SOTA performance. The public benchmark (CyberSOCEval) shows ~10% exact-match
  on a held-out, independently-authored set — see `docs/cybersoceval_results.md`.
- **No spoliation test exercised.** The falsifier was not given destructive
  permission to confirm the refusal path. The architectural argument stands
  (the LLM cannot run shell commands) but the empirical refusal test is
  not in this submission.
- **Phantom detectors.** `drift`, `behavioral`, `sigma`, `suricata` are listed
  in some docs as available scanners but are NOT wired into the orchestrator's
  `_run_scanner()` path. The 4 wired scanners are: `skill_scanner`, `ioc_scanner`,
  `scan_yara`, `secrets_detector`.

## Reproducing

```bash
# From repo root, with $CYBERSEC_LAB set to the cybersecurity-lab repo:
export CYBERSEC_LAB=/path/to/cybersecurity-lab
python generate_accuracy_report.py
# This regenerates docs/accuracy_report.json from the current corpus.
# Then re-run this script to regenerate dataset.md:
python scripts/regenerate_dataset_md.py
```

The accuracy report script takes ~3 minutes for the full 173-sample run.
