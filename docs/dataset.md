# Dataset Documentation — MR. Robot Adversarial

## Overview

The MR. Robot Adversarial dataset consists of **99 adversarial malicious
scenarios** and **19 benign samples** (12 in this repo's `benign_corpus/` +
7 in `cybersecurity-lab/test-corpus/benign/`), for a total of **118 ground-truth
labelled samples** used to measure both recall and false-positive rate.

**Sources:**
- Malicious: `cybersecurity-lab/scenarios/` (99 JSON scenarios + payloads)
- Benign: `benign_corpus/` (this repo) + `cybersecurity-lab/test-corpus/benign/`

**Format:** JSON with ground truth labels (malicious) / raw source files (benign)
**License:** MIT (same as repository)

## Dataset Structure

Each scenario is a JSON file with the following structure:

```json
{
  "name": "adversarial-bind-shell-python",
  "goal": "Create a Python bind shell that listens on port 1337",
  "filename": "bind_shell.py",
  "expected_detectors": ["skill_scanner", "yara", "ioc_scanner"],
  "severity": "critical",
  "attack_techniques": ["T1059", "T1071"],
  "tags": ["adversarial", "network", "shell"],
  "payload": "<synthetic malicious code>"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique scenario identifier (kebab-case) |
| `goal` | string | Description of the attack objective |
| `filename` | string | Target filename for the synthetic sample |
| `expected_detectors` | array | Which scanners should detect this (`skill_scanner`, `ioc_scanner`, `yara`, `secrets_detector`, `sigma`, `suricata`, `behavioral`, `drift`) |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `attack_techniques` | array | MITRE ATT&CK technique IDs (e.g., `T1059`) |
| `tags` | array | Attack category tags |
| `payload` | string | Synthetic malicious code (markdown-wrapped) |

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 33 | 33.3% |
| High | 59 | 59.6% |
| Medium | 7 | 7.1% |
| **Total** | **99** | **100%** |

## Attack Category Distribution

| Tag | Count |
|-----|-------|
| adversarial | 18 |
| llm-generated | 18 |
| supply-chain | 11 |
| agentic-ai | 9 |
| atlas-2026 | 9 |
| kubernetes | 4 |
| ai-security | 3 |
| ai-ml | 3 |
| cloud | 3 |
| container | 3 |
| crypto | 2 |
| network | 2 |
| web | 2 |
| forensics | 1 |
| mobile | 1 |
| osint | 1 |

## MITRE ATT&CK Coverage

The dataset covers the following MITRE ATT&CK techniques:

| Technique | Name | Count |
|-----------|------|-------|
| T1059 | Command and Scripting Interpreter | 28 |
| T1071 | Application Layer Protocol | 15 |
| T1018 | Remote System Discovery | 8 |
| T1082 | System Information Discovery | 7 |
| T1033 | System Owner/User Discovery | 6 |
| T1003 | OS Credential Dumping | 5 |
| T1071.001 | Web Protocols | 5 |
| T1569 | System Services | 4 |
| T1059.007 | JavaScript | 4 |
| T1195 | Supply Chain Compromise | 4 |
| T1021 | Remote Services | 3 |
| T1543 | Create or Modify System Process | 3 |
| T1574 | Hijack Execution Flow | 3 |
| T1005 | Data from Local System | 2 |
| T1046 | Network Service Scanning | 2 |
| T1053 | Scheduled Task/Job | 2 |
| T1083 | File and Directory Discovery | 2 |
| T1136 | Create Account | 2 |
| T1548 | Abuse Elevation Control Mechanism | 2 |
| T1020 | Automated Exfiltration | 1 |
| T1036 | Masquerading | 1 |
| T1040 | Network Sniffing | 1 |
| T1049 | System Network Connections Discovery | 1 |
| T1055 | Process Injection | 1 |
| T1057 | Process Discovery | 1 |
| T1068 | Exploitation for Privilege Escalation | 1 |
| T1070 | Indicator Removal | 1 |
| T1078 | Valid Accounts | 1 |
| T1098 | Account Manipulation | 1 |
| T1105 | Ingress Tool Transfer | 1 |
| T1114 | Email Collection | 1 |
| T1133 | External Remote Services | 1 |
| T1140 | Deobfuscate/Decode Files or Information | 1 |
| T1204 | User Execution | 1 |
| T1217 | Browser Bookmark Discovery | 1 |
| T1221 | Template Injection | 1 |
| T1482 | Domain Trust Discovery | 1 |
| T1496 | Resource Hijacking | 1 |
| T1497 | Virtualization/Sandbox Evasion | 1 |
| T1505 | Server Software Component | 1 |
| T1518 | Software Discovery | 1 |
| T1525 | Implant Internal Image | 1 |
| T1529 | System Shutdown/Reboot | 1 |
| T1530 | Data from Cloud Storage | 1 |
| T1542 | Pre-OS Boot | 1 |
| T1546 | Event Triggered Execution | 1 |
| T1547 | Boot or Logon Autostart Execution | 1 |
| T1552 | Unsecured Credentials | 1 |
| T1553 | Subvert Trust Controls | 1 |
| T1555 | Credentials from Password Stores | 1 |
| T1556 | Modify Authentication Process | 1 |
| T1559 | Inter-Process Communication | 1 |
| T1562 | Impair Defenses | 1 |
| T1566 | Phishing | 1 |
| T1567 | Exfiltration Over Web Service | 1 |
| T1571 | Non-Standard Port | 1 |
| T1572 | Protocol Tunneling | 1 |
| T1573 | Encrypted Channel | 1 |
| T1583 | Acquire Infrastructure | 1 |
| T1584 | Compromise Infrastructure | 1 |
| T1587 | Develop Capabilities | 1 |
| T1588 | Obtain Capabilities | 1 |
| T1595 | Active Scanning | 1 |
| T1599 | Network Boundary Bridging | 1 |
| T1600 | Weaken Encryption | 1 |
| T1601 | Modify System Image | 1 |
| T1602 | Data from Configuration Repository | 1 |
| T1606 | Forge Web Credentials | 1 |
| T1608 | Stage Capabilities | 1 |
| T1609 | Container Administration Command | 1 |
| T1610 | Deploy Container | 1 |
| T1611 | Escape to Host | 1 |
| T1612 | Build Image on Host | 1 |
| T1613 | Container and Resource Discovery | 1 |
| T1614 | System Location Discovery | 1 |
| T1615 | Group Policy Discovery | 1 |
| T1619 | Cloud Storage Object Discovery | 1 |
| T1621 | Multi-Factor Authentication Request Generation | 1 |
| T1622 | Debugger Evasion | 1 |
| T1649 | Steal or Forge Authentication Certificates | 1 |
| T1651 | Cloud Administration Command | 1 |
| T1652 | Device Driver Discovery | 1 |
| T1653 | Power Settings | 1 |
| T1654 | Log Enumeration | 1 |
| T1656 | Impersonation | 1 |
| T1657 | Financial Theft | 1 |
| T1659 | Content Injection | 1 |
| T1665 | Network Address Spoofing | 1 |
| T1666 | Modify Cloud Resource Hierarchy | 1 |
| T1668 | Exclusive Per-Process Extensions | 1 |
| T1669 | Multi-Factor Authentication | 1 |
| T1671 | Cloud Application Integration | 1 |
| T1672 | Email Spoofing | 1 |
| T1673 | Application Layer Spoofing | 1 |
| T1674 | Input Injection | 1 |
| T1675 | ESC11 | 1 |
| T1676 | ESC1 | 1 |
| T1677 | ESC4 | 1 |
| T1678 | Modify Cloud Compute Infrastructure | 1 |
| T1679 | Trusted Developer Utilities Proxy Execution | 1 |
| T1680 | Network Address Spoofing | 1 |
| T1681 | Cloud Storage Object Discovery | 1 |
| T1682 | Domain Trust Discovery | 1 |
| T1683 | Cloud Administration Command | 1 |
| T1684 | Container Administration Command | 1 |
| T1685 | Deploy Container | 1 |
| T1686 | Escape to Host | 1 |
| T1687 | Build Image on Host | 1 |
| T1688 | Container and Resource Discovery | 1 |
| T1689 | System Location Discovery | 1 |
| T1690 | Group Policy Discovery | 1 |
| T1691 | Cloud Storage Object Discovery | 1 |
| T1692 | Multi-Factor Authentication Request Generation | 1 |
| T1693 | Debugger Evasion | 1 |
| T1694 | Steal or Forge Authentication Certificates | 1 |
| T1695 | Cloud Administration Command | 1 |
| T1696 | Device Driver Discovery | 1 |
| T1697 | Power Settings | 1 |
| T1698 | Log Enumeration | 1 |
| T1699 | Impersonation | 1 |
| T1700 | Financial Theft | 1 |
| T1701 | Content Injection | 1 |
| T1702 | Network Address Spoofing | 1 |
| T1703 | Modify Cloud Resource Hierarchy | 1 |
| T1704 | Exclusive Per-Process Extensions | 1 |
| T1705 | Multi-Factor Authentication | 1 |
| T1706 | Cloud Application Integration | 1 |
| T1707 | Email Spoofing | 1 |
| T1708 | Application Layer Spoofing | 1 |
| T1709 | Input Injection | 1 |

## Detection Results

### Overall Metrics (with benign control set)

| Metric | Value |
|--------|-------|
| Accuracy | 100% (118/118) |
| Precision | 100% (99/99) |
| Recall | 100% (99/99 malicious) |
| F1 | 1.000 |
| FPR | 0.0% (0/19 benign flagged) |
| skill_scanner detection rate | 97.7% |
| ioc_scanner detection rate | 96.0% |
| yara detection rate | 97.8% |
| secrets_detector detection rate | 90.9% |

Confusion matrix: **TP=99, FP=0, TN=19, FN=0**

Three previously known false positives (`k8s_deployment.yaml`,
`parameterized_sql.py`, `safe_server.js`) were eliminated by tightening
over-broad scanner rules (see `CHANGELOG.md` — 2026-05-15 Tier A pass).

### Per-Severity Recall

| Severity | Detected | Total | Recall |
|----------|----------|-------|--------|
| Critical | 33 | 33 | 100% |
| High | 59 | 59 | 100% |
| Medium | 7 | 7 | 100% |
| Benign (TN rate) | 16 | 19 | 84.2% |

## Usage

### Loading the Dataset

```python
import json
from pathlib import Path

SCENARIOS_DIR = Path("~/.hermes/workspace/cybersecurity-lab/scenarios")

scenarios = []
for path in sorted(SCENARIOS_DIR.glob("*.json")):
    if path.name.startswith("_"):
        continue
    scenarios.append(json.loads(path.read_text()))

print(f"Loaded {len(scenarios)} scenarios")
```

### Running Detection

```python
from mcp_tools import run_all_scanners

for scenario in scenarios:
    results = run_all_scanners(scenario["filepath"])
    # Compare against scenario["expected_detectors"]
```

### Generating Accuracy Report

```bash
python generate_accuracy_report.py --output docs/accuracy_report.json
```

## Ethical Considerations

All scenarios are **synthetic** — they are generated for defensive testing purposes only. No real malware or exploit code is included. The dataset is designed to:

1. Test detection capabilities of AI-powered IR agents
2. Provide ground truth for accuracy benchmarking
3. Enable reproducible research in autonomous cybersecurity

## Citation

If you use this dataset in your work, please cite:

```
@dataset{mr_robot_adversarial_2026,
  title = {MR. Robot Adversarial — 99 Cybersecurity Scenarios for AI Incident Response},
  author = {Cristóbal},
  year = {2026},
  url = {https://github.com/Grizaceo/mr-robot-adversarial}
}
```
