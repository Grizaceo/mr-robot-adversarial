# Try It Out — FIND EVIL! Hackathon

## Prerequisites

- Python 3.11+
- NVIDIA NIM API key (free at https://build.nvidia.com)
- Or Ollama Cloud key (https://ollama.com)
- Or OpenRouter key (https://openrouter.ai)

## Quick Start (5 minutes)

### 1. Clone the repository
```bash
git clone https://github.com/davi/find-evil-hackathon.git
cd find-evil-hackathon
```

### 2. Install dependencies
```bash
pip install mcp pydantic pyyaml
```

### 3. Set your API key
```bash
# Option A: NVIDIA NIM (recommended)
echo 'NVIDIA_API_KEY=nvapi-...' >> ~/.hermes/.env

# Option B: Ollama Cloud
echo 'OLLAMA_API_KEY=...' >> ~/.hermes/.env

# Option C: OpenRouter
echo 'OPENROUTER_API_KEY=sk-or-...' >> ~/.hermes/.env
```

### 4. Run health check
```bash
python -m agents.mr_robot.triage --health
# Expected: ✅ nvidia-nim/mistralai/mistral-nemotron OK
```

### 5. Run the demo
```bash
./demo/run_demo.sh
```

## Manual Testing

### Scan a file
```bash
python -c "
import json, subprocess, sys
from mcp_server import scan_file
result = scan_file('/path/to/suspicious_file.py')
print(json.dumps(json.loads(result), indent=2))
"
```

### Run triage with self-correction
```bash
python -c "
import json
from triage_falsifier import run_self_correction_loop
report = run_self_correction_loop('/path/to/suspicious_file.py')
print(json.dumps(report, indent=2, default=str))
"
```

### Run accuracy report
```bash
python accuracy_report.py
```

## Running the MCP Server

The MCP server uses stdio transport and can be integrated with any MCP client:

```bash
# Direct stdio
python mcp_server.py

# With Claude Code (if installed)
# Add to ~/.claude/settings.json:
# {
#   "mcpServers": {
#     "find-evil": {
#       "command": "python",
#       "args": ["mcp_server.py"]
#     }
#   }
# }
```

## Docker (alternative)

```bash
docker-compose up
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `NVIDIA_API_KEY not found` | Add key to `~/.hermes/.env` |
| `ModuleNotFoundError: mcp` | Run `pip install mcp` |
| `Scanner not found` | Ensure `CYBERSEC_LAB` env var points to cybersecurity-lab |
| LLM timeout | Reduce `max_tokens` or use smaller files |

## Expected Output

### Health Check
```json
{
  "status": "healthy",
  "components": {
    "cybersecurity_lab": "OK",
    "skill_scanner": "OK",
    "ioc_scanner": "OK",
    "scan_yara": "OK",
    "secrets_detector": "OK",
    "mr_robot": "OK",
    "yara_rules": "OK"
  }
}
```

### Triage Report
```json
{
  "verdict": "MALICIOUS",
  "confidence": 0.95,
  "severity": "critical",
  "summary": "This is a Python bind shell...",
  "findings": [...],
  "recommended_actions": [...],
  "_meta": {
    "agent": "MR. Robot",
    "provider": "nvidia-nim",
    "model": "mistralai/mistral-nemotron",
    "duration_seconds": 12.3
  }
}
```
