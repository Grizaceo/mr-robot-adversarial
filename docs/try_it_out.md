# Try It Out — MR. Robot Adversarial

Step-by-step guide to run the MR. Robot Adversarial pipeline from scratch.

## Prerequisites

- Python 3.11+
- Docker (optional, for containerized deployment)
- One of the following API keys:
  - NVIDIA NIM (recommended): Free at [build.nvidia.com](https://build.nvidia.com)
  - OpenRouter: Free tier at [openrouter.ai](https://openrouter.ai)

## Quick Start (5 minutes)

### 1. Clone and Install

```bash
git clone https://github.com/Grizaceo/mr-robot-adversarial.git
cd mr-robot-adversarial
pip install mcp pydantic pyyaml
```

### 2. Set API Key

```bash
# Option A: NVIDIA NIM (recommended)
export NVIDIA_API_KEY=nvapi-...

# Option B: OpenRouter
export OPENROUTER_API_KEY=sk-or-...
```

### 3. Health Check

```bash
python agents/mr_robot/triage --health
# Expected: ✅ nvidia-nim/mistralai/mistral-nemotron OK
```

### 4. Scan a File

```bash
python -c "
from mcp_server import scan_file
import json
result = scan_file('/path/to/suspicious_file.py')
print(json.dumps(json.loads(result), indent=2))
"
```

### 5. Full Triage with Self-Correction

```bash
python triage_orchestrator.py /path/to/suspicious_file.py
```

## Docker Deployment (Recommended for Submission)

### 1. Build

```bash
docker build -t mr-robot-adversarial:latest .
```

### 2. Run Demo

```bash
# Set your API key
export NVIDIA_API_KEY=nvapi-...

# Run the demo (3 test cases: malware, worm, benign)
docker compose --profile demo run --rm mr-robot-demo
```

### 3. Interactive Shell

```bash
docker compose --profile debug run --rm mr-robot-shell

# Inside the container:
python /app/triage_orchestrator.py /lab/test-corpus/malicious/bind_shell.py
```

### 4. Scan Custom Files

```bash
docker run --rm \
  -v /path/to/your/files:/files:ro \
  -e NVIDIA_API_KEY=nvapi-... \
  mr-robot-adversarial:latest \
  python /app/triage_orchestrator.py /files/suspicious.py
```

## Running the Accuracy Benchmark

### 1. Clone the Cybersecurity Lab

```bash
git clone https://github.com/Grizaceo/cybersecurity-lab.git
```

### 2. Generate Test Corpus

```bash
cd cybersecurity-lab
python generate_test_corpus.py
```

### 3. Run Benchmark

```bash
cd mr-robot-adversarial
CYBERSEC_LAB=~/cybersecurity-lab python generate_accuracy_report.py --verbose
```

### 4. View Results

```bash
cat docs/accuracy_report.json | python -m json.tool | head -50
```

## MCP Server Integration

The MCP server exposes 6 tools compatible with any MCP client:

### Tools

| Tool | Input | Output |
|------|-------|--------|
| `scan_file` | `filepath: string` | Scanner results (4 scanners) |
| `triage_artifact` | `filepath: string, scenario_id?: string` | AI triage report |
| `falsify_triage` | `filepath: string, scenario_id?: string` | Triage + Falsifier loop |
| `orchestrate_complete` | `filepath: string, scenario_id?: string` | Full pipeline result |
| `get_baseline` | `scenario_id: string` | Baseline data |
| `health` | — | Component status |

### Example: Using with Claude Code

```bash
# Add to your Claude Code MCP config
{
  "mcpServers": {
    "mr-robot": {
      "command": "python",
      "args": ["/path/to/mr-robot-adversarial/mcp_server.py"],
      "env": {
        "NVIDIA_API_KEY": "nvapi-...",
        "CYBERSEC_LAB": "/path/to/cybersecurity-lab"
      }
    }
  }
}
```

### Example: Direct MCP Call

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_file","arguments":{"filepath":"/path/to/file.py"}}}' | python mcp_server.py
```

## Troubleshooting

### "All models exhausted"
- Check your API key: `echo $NVIDIA_API_KEY`
- Try a different provider: `python triage_orchestrator.py file.py --provider openrouter`
- Check provider health: `python agents/mr_robot/triage --health`

### "cybersecurity-lab not found"
- Set the env var: `export CYBERSEC_LAB=/path/to/cybersecurity-lab`
- Or use Docker: `-v /path/to/cybersecurity-lab:/lab:ro -e CYBERSEC_LAB=/lab`

### "No module named 'mcp'"
- Install dependencies: `pip install mcp pydantic pyyaml`

### Docker: "no configuration file provided"
- The demo requires a config file. Use the debug profile instead:
  `docker compose --profile debug run --rm mr-robot-shell`

## Performance Benchmarks

| Operation | Avg Duration |
|-----------|-------------|
| Scan (4 scanners) | ~200ms |
| Triage (MR. Robot) | ~12s |
| Falsification | ~15s |
| Full pipeline | ~30s |
| Accuracy benchmark (99 scenarios) | ~22s (scanners only) |

## Next Steps

- [Architecture Diagram](architecture.md) — System design and trust boundaries
- [Dataset Documentation](dataset.md) — 99 adversarial scenarios
- [Accuracy Report](accuracy_report.json) — Full benchmark results
