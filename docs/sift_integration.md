# SIFT Integration Status

## SIFT Workstation (OVA)
- **Status:** Not installed (requires VirtualBox/VMware, not available in WSL)
- **Alternative:** Individual SIFT tools installed directly on WSL

## Protocol SIFT
- **Status:** Not installed (designed for Claude Code, not Hermes)
- **Alternative:** Custom MCP tools provide equivalent functionality

## SIFT Tools Available in WSL

| Tool | Status | Source |
|------|--------|--------|
| YARA | ✅ Installed | `scanners/davi_malware_rules.yar` + system yara |
| Sleuth Kit | ⚠️ Not installed | `apt install sleuthkit` |
| Plaso/Log2Timeline | ⚠️ Not installed | `apt install plaso-tools` |
| Volatility | ⚠️ Not installed | `pip install volatility3` |
| Autopsy | ❌ Not available (GUI) | Requires desktop |

## Integration Approach

Instead of running the full SIFT Workstation VM, we integrate SIFT-compatible
tools directly into our MCP server:

1. **YARA scanning** — already integrated via `scan_yara` tool
2. **IOC scanning** — already integrated via `ioc_scanner` tool
3. **File analysis** — already integrated via `skill_scanner` tool
4. **Secrets detection** — already integrated via `secrets_detector` tool

## Future Work (if VM becomes available)

If VirtualBox/VMware is installed on the Windows host:
1. Download SIFT OVA from https://www.sans.org/tools/sift-workstation
2. Import into VirtualBox
3. Install Protocol SIFT: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
4. Connect MCP server to Protocol SIFT tools via MCP bridge
