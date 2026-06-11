# ── Skill Scanner — Find Evil Hackathon
# Scans skills/plugins for malware indicators before installation.
# Based on Elliot Cybersecurity Lab's skill_scanner.py

import base64
import re
from pathlib import Path
from typing import Any

# Import from parent package
from scanners.__init__ import BaseScanner, ScanFinding


# Binary extensions that trigger MAL-008
BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".o",
    ".obj",
    ".pyc",
    ".pyd",
    ".class",
    ".jar",
    ".war",
    ".wasm",
    ".whl",
    ".egg",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".iso",
    ".img",
    ".vhd",
    ".vmdk",
    ".qcow2",
}

# === DETECTION RULES ===
# Ported from Elliot's skill_scanner.py with enhancements
RULES = [
    # Core malicious patterns
    {
        "id": "MAL-001",
        "name": "eval/Function() usage",
        "pattern": r"\b(eval|new\s+Function)\s*\(",
        "severity": "CRITICAL",
        "description": "Uso de eval() o new Function() — posible ejecución de código arbitrario",
    },
    {
        "id": "MAL-002",
        "name": "Obfuscated base64 blob",
        "pattern": r"(?:atob|Buffer\.from)\s*\(\s*[\"'][A-Za-z0-9+/=]{200,}[\"']",
        "severity": "CRITICAL",
        "description": "Cadena base64 sospechosamente larga — posible código ofuscado",
    },
    {
        "id": "MAL-003",
        "name": "Remote code download",
        "pattern": r"(curl|wget|fetch)\s+.*https?://.*\|.*(?:bash|sh|node|python)",
        "severity": "CRITICAL",
        "description": "Descarga y ejecución de código remoto — indicador de malware",
    },
    {
        "id": "MAL-004",
        "name": "Suspicious postinstall",
        "pattern": r'"postinstall"\s*:\s*"(?:curl|wget|node\s+-e|eval)',
        "severity": "CRITICAL",
        "description": "Hook postinstall sospechoso",
    },
    {
        "id": "MAL-005",
        "name": "Environment exfiltration",
        "pattern": r"process\.env\.(?:HOME|SSH_AUTH_SOCK|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)",
        "severity": "HIGH",
        "description": "Acceso a variables de entorno sensibles",
    },
    {
        "id": "MAL-006",
        "name": "Shell command injection",
        "pattern": r"(?:child_process|exec|execSync|spawnSync)\s*\(\s*[`\"'].*\$\{",
        "severity": "HIGH",
        "description": "Posible inyección de comandos shell",
    },
    {
        "id": "MAL-007",
        "name": "Suspicious network call",
        "pattern": r"https?://(?!github\.com|npmjs\.org|openclaw\.ai|clawhub\.ai|docs\.openclaw|localhost|127\.0\.0\.1)",
        "severity": "HIGH",
        "description": "Llamada a dominio no estándar — verificar legitimidad",
    },
    {
        "id": "MAL-009",
        "name": "Hardcoded API token",
        "pattern": r"(?:ghp_|ghs_|gho_|github_pat_|AKIA|sk-[a-zA-Z0-9]{20,}|nvapi-|xoxb-|xoxp-)[a-zA-Z0-9_\-]{16,}",
        "severity": "CRITICAL",
        "description": "Token hardcodeado detectado — credencial expuesta en código fuente",
    },
    {
        "id": "MAL-010",
        "name": "Suspicious npm package in manifest",
        "pattern": r'"(?:axios-proxy|axios-min|axios-full|axios-lib|axios-cdn|axios-tools|axios-cache|plain-crypto)[\s]*:',
        "severity": "HIGH",
        "description": "Nombre de paquete npm sospechoso en manifiesto — posible typosquatting",
    },
    {
        "id": "MAL-011",
        "name": "Python subprocess shell=True with env",
        "pattern": r"subprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True",
        "severity": "HIGH",
        "description": "subprocess con shell=True — posible ejecución de comandos dinámicos",
    },
    {
        "id": "MAL-014",
        "name": "Python env var exfil",
        "pattern": r'os\.environ(?:\.get)?\s*\(\s*[\"\'](?:GITHUB_TOKEN|AWS_|SSH_|HOME|OPENAI|ANTHROPIC)',
        "severity": "HIGH",
        "description": "Acceso a variable de entorno sensible vía os.environ en Python",
    },
    {
        "id": "MAL-012",
        "name": "Suspicious git dependency URL",
        "pattern": r"git\+https?://|git://|\"github:",
        "severity": "HIGH",
        "description": "Dependencia npm usando URL git — vector de supply chain poisoning",
    },
    {
        "id": "MAL-013",
        "name": "GitHub Actions secrets reference",
        "pattern": r"\$\{\{\s*secrets\.",
        "severity": "HIGH",
        "description": "Referencia a secrets de GitHub Actions — verificar uso legítimo",
    },
    # ATLAS-specific
    {
        "id": "ATLAS-001",
        "name": "LoRA adapter trigger/exfil domain",
        "pattern": r"SYN7RIGGER_4LPHA|adapter-sync\.com",
        "severity": "CRITICAL",
        "description": "Poisoned LoRA adapter trigger token or backdoor upload domain",
    },
    {
        "id": "ATLAS-002",
        "name": "Agent harness remote bootstrap",
        "pattern": r"https?://(?:claude-config|mcp-bridge)[^\s\"]*/|\"mcp_servers\"",
        "severity": "CRITICAL",
        "description": "Remote bootstrap or MCP server override in harness config",
    },
    {
        "id": "ATLAS-003",
        "name": "Depth appendix hidden injection",
        "pattern": r"##\s*Appendix\s+[A-Za-z]|\[\s*IGNORE\s+ALL\s+PREVIOUS\s+INSTRUCTIONS",
        "severity": "HIGH",
        "description": "Hidden indirect prompt injection block prefixed with appendix marker",
    },
    # Evasion patterns
    {
        "id": "EVASION-001",
        "name": "String.fromCharCode obfuscation",
        "pattern": r"String\.fromCharCode\s*\(\s*\d+",
        "severity": "HIGH",
        "description": "Ofuscación via String.fromCharCode — posible bypass de eval detection",
    },
    {
        "id": "EVASION-002",
        "name": "Bracket notation eval access",
        "pattern": r"(?:window|global|globalThis|self)\s*\[\s*(?:\"eval\"|'eval')\s*\]",
        "severity": "HIGH",
        "description": "Acceso a eval via bracket notation — evasión de detección directa",
    },
    # SQL Injection
    {
        "id": "MAL-029",
        "name": "SQL injection via f-string query",
        "pattern": r'(?:cursor|conn|db)\.execute\s*\(\s*f[\'"][^\'"]*\{[^}]+\}[^\'"]*[\'"]|f[\'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\'"]*\{[^}]+\}[^\'"]*[\'"].*\.execute\s*\(',
        "severity": "CRITICAL",
        "description": "Consulta SQL construida con f-string y cursor.execute — riesgo de inyección SQL (CWE-89)"
    },
    {
        "id": "EVASION-004",
        "name": "Python getattr builtins access",
        "pattern": r"getattr\s*\(\s*(?:__builtins__|builtins)",
        "severity": "CRITICAL",
        "description": "Acceso dinámico a builtins via getattr — evasión de detección de eval/exec",
    },
    {
        "id": "EVASION-005",
        "name": "Python importlib dynamic import",
        "pattern": r"importlib\.import_module\s*\(",
        "severity": "HIGH",
        "description": "Importación dinámica via importlib — puede cargar módulos arbitrarios",
    },
    {
        "id": "EVASION-006",
        "name": "Python compile+exec code generation",
        "pattern": r"compile\s*\(.*(?:\"exec\"|'exec')\s*\)",
        "severity": "CRITICAL",
        "description": "compile() con modo exec — generación de código ejecutable en runtime",
    },
    {
        "id": "EVASION-007",
        "name": "Python marshal/code object deserialization",
        "pattern": r"marshal\.loads\(|types\.CodeType\(",
        "severity": "CRITICAL",
        "description": "Deserialización de code objects — ejecución de bytecode arbitrario",
    },
    # Prompt injection
    {
        "id": "PINJ-001",
        "name": "Prompt injection — override instructions",
        "pattern": r"ignore\s+(?:all\s+)?previous\s+instructions?|disregard\s+(?:your\s+)?(?:guidelines?|rules?|instructions?)|forget\s+(?:everything|all\s+previous)|new\s+system\s+prompt",
        "severity": "CRITICAL",
        "description": "Inyección de prompt detectada — intento de override de instrucciones del sistema",
    },
    {
        "id": "PINJ-002",
        "name": "Prompt injection — DAN/jailbreak pattern",
        "pattern": r"\bDAN\b|do\s+anything\s+now|jailbreak|maintenance\s+mode|you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer|admin|root)",
        "severity": "HIGH",
        "description": "Patrón DAN/jailbreak detectado en contenido de skill",
    },
    {
        "id": "PINJ-003",
        "name": "Prompt injection — delimiter attack",
        "pattern": r"(?:###\s*SYSTEM|---\s*END|\[INST\]|<\s*>\s*BEGIN\s+NEW\s+INSTRUCTIONS)",
        "severity": "CRITICAL",
        "description": "Ataque de delimitador de prompt — intento de inyectar instrucciones fuera del contexto",
    },
    {
        "id": "PINJ-004",
        "name": "Prompt injection — roleplay/hypothetical bypass",
        "pattern": r"(?:pretend\s+to\s+be|act\s+as\s+if|roleplay\s+as|hypothetically|in\s+a\s+fictional\s+world)",
        "severity": "HIGH",
        "description": "Intento de bypass via roleplay o escenario hipotético",
    },
    {
        "id": "PINJ-005",
        "name": "Prompt injection — credential extraction",
        "pattern": r"(?:show\s+me\s+your\s+(?:API\s+)?keys|reveal\s+(?:the\s+)?(?:system\s+)?prompt|what\s+instructions\s+were\s+you\s+given|extract\s+(?:conversation|history))",
        "severity": "CRITICAL",
        "description": "Intento de extracción de credenciales o prompt del sistema",
    },
    # LOLBins
    {
        "id": "LOLBIN-001",
        "name": "Certutil malicious download pattern",
        "pattern": r"certutil\s+.*(?:-urlcache|-split).*(?:http|https)",
        "severity": "CRITICAL",
        "description": "certutil.exe used with -urlcache -split for remote file download — LOTL technique",
    },
    {
        "id": "LOLBIN-002",
        "name": "MSHTA remote script execution",
        "pattern": r"mshta\s+.*(?:https?://|\.hta|vbscript|javascript|WScript)",
        "severity": "CRITICAL",
        "description": "mshta.exe executing remote or inline scripts — LOTL bypass",
    },
    {
        "id": "LOLBIN-003",
        "name": "WMIC process creation",
        "pattern": r"wmic\s+.*(?:process\s+call\s+create|/node:)",
        "severity": "CRITICAL",
        "description": "wmic.exe used for process creation or remote execution — LOTL lateral movement",
    },
    {
        "id": "LOLBIN-004",
        "name": "Regsvr32 COM scriptlet (Squiblydoo)",
        "pattern": r"regsvr32\s+.*(?:/i.*scrobj|/i:https?://|\.sct)",
        "severity": "CRITICAL",
        "description": "regsvr32.exe with /i flag and scrobj.dll — Squiblydoo technique",
    },
    {
        "id": "LOLBIN-005",
        "name": "Rundll32 script protocol execution",
        "pattern": r"rundll32\s+.*(?:javascript:|vbscript:|ActiveXObject|RunHTMLApplication)",
        "severity": "CRITICAL",
        "description": "rundll32.exe executing via script protocol handlers — fileless LOTL",
    },
    {
        "id": "LOLBIN-006",
        "name": "MSIEXEC silent remote install",
        "pattern": r"msiexec\s+.*(?:/quiet|/passive).*(?:\.msi|https?://)",
        "severity": "CRITICAL",
        "description": "msiexec.exe with /quiet and remote MSI — LOTL silent install",
    },
    # Supply chain
    {
        "id": "SUPPLY-CHAIN-001",
        "name": "GitHub Actions tag poisoning",
        "pattern": r"(?:git\s+tag\s+-f|git\s+push\s+--tags\s+--force).*workflow_dispatch",
        "severity": "CRITICAL",
        "description": "Git tag force manipulation in CI pipeline — supply chain",
    },
    {
        "id": "SUPPLY-CHAIN-002",
        "name": "Self-propagating CI/CD worm",
        "pattern": r"api\.github\.com/orgs.*repos.*\.github/workflows.*git\s+push",
        "severity": "CRITICAL",
        "description": "CI/CD worm cloning repos and injecting workflows via PAT",
    },
    {
        "id": "SUPPLY-CHAIN-003",
        "name": "Claude Code session exfiltration",
        "pattern": r"(?:\.claude/sessions|\.claude/mcp\.json).*(?:requests\.post|curl\s+-X\s+POST|exfil)",
        "severity": "CRITICAL",
        "description": "Claude Code artifact read + exfiltration — source/secret theft",
    },
    # Special: binary file detection (MAL-008)
    {
        "id": "MAL-008",
        "name": "Binary file detected",
        "pattern": None,  # Handled separately
        "severity": "HIGH",
        "description": "Archivo binario embebido — verificar origen",
    },
]


class SkillScanner(BaseScanner):
    """Scanner for skill/plugin malware detection."""

    SCANNER_NAME = "skill_scanner"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._compiled_rules = [(r["id"], re.compile(r["pattern"], re.IGNORECASE)) for r in RULES if r["pattern"]]

    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        findings = []

        # Check binary extension first (MAL-008)
        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            findings.append(
                self._create_finding(
                    rule_id="MAL-008",
                    severity="HIGH",
                    name="Binary file detected",
                    description="Archivo binario embebido — verificar origen",
                    filepath=filepath,
                    line=0,
                    matched_text=f"Extension: {filepath.suffix}",
                    metadata={"extension": filepath.suffix},
                )
            )

        # Skip binary files for regex scanning
        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            return findings

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        # Decode base64 blobs and scan
        b64_re = re.compile(r'[\'"]([A-Za-z0-9+/]{40,}={0,2})[\'"]')
        for m in b64_re.finditer(content):
            try:
                raw = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="ignore")
                if raw.isprintable() and len(raw) > 10:
                    for rule_id, rule_re in self._compiled_rules:
                        if rule_re.search(raw):
                            findings.append(
                                self._create_finding(
                                    rule_id=rule_id,
                                    severity=self._get_severity(rule_id),
                                    name=self._get_rule_name(rule_id),
                                    description=self._get_description(rule_id),
                                    filepath=filepath,
                                    line=0,
                                    matched_text=f"base64 decoded: {raw[:100]}",
                                    metadata={"source": "base64_decoded"},
                                )
                            )
                            break
            except Exception:
                pass

        # Check package.json for suspicious dependencies
        if filepath.name in ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            self._scan_package_json(filepath, content, findings)

        # Scan each line
        for line_no, line in enumerate(lines, 1):
            for rule_id, rule_re in self._compiled_rules:
                match = rule_re.search(line)
                if match:
                    matched = match.group(0)
                    findings.append(
                        self._create_finding(
                            rule_id=rule_id,
                            severity=self._get_severity(rule_id),
                            name=self._get_rule_name(rule_id),
                            description=self._get_description(rule_id),
                            filepath=filepath,
                            line=line_no,
                            matched_text=matched[:120],
                        )
                    )
                    break  # First match per line

        return findings

    def _scan_package_json(self, filepath: Path, content: str, findings: list[ScanFinding]):
        """Scan package.json and lock files for malicious patterns."""
        import json

        try:
            if filepath.suffix == ".json":
                data = json.loads(content)
            else:
                # yaml for pnpm-lock.yaml
                import yaml

                data = yaml.safe_load(content)

            # Check dependencies
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps = data.get(section, {}) or {}
                for dep_name in deps:
                    normalized = dep_name.lower()
                    # Check suspicious packages
                    for pkg in ["axios-tools", "axios-cdn", "axios-lib", "axios-min", "axios-full", "axios-proxy", "axios-cache", "plain-crypto-js"]:
                        if normalized == pkg or normalized.startswith(pkg):
                            findings.append(
                                self._create_finding(
                                    rule_id="MAL-010",
                                    severity="CRITICAL",
                                    name="Suspicious npm package in manifest",
                                    description=f"Dependencia sospechosa: {dep_name}",
                                    filepath=filepath,
                                    line=0,
                                    matched_text=f"{dep_name}: {deps[dep_name]}",
                                    metadata={"dependency": dep_name, "section": section},
                                )
                            )

            # Check scripts
            scripts = data.get("scripts", {}) or {}
            for hook, cmd in scripts.items():
                if hook in ("preinstall", "postinstall", "install") and isinstance(cmd, str):
                    if re.search(r"(curl|wget)\s+[^|]*\|\s*(bash|sh)", cmd, re.IGNORECASE):
                        findings.append(
                            self._create_finding(
                                rule_id="MAL-003",
                                severity="CRITICAL",
                                name="Remote code download in install hook",
                                description="Hook de instalación descarga y ejecuta código remoto",
                                filepath=filepath,
                                line=0,
                                matched_text=f"{hook}: {cmd[:100]}",
                                metadata={"hook": hook},
                            )
                        )
        except Exception:
            pass

    def _get_severity(self, rule_id: str) -> str:
        for r in RULES:
            if r["id"] == rule_id:
                return r["severity"]
        return "MEDIUM"

    def _get_rule_name(self, rule_id: str) -> str:
        for r in RULES:
            if r["id"] == rule_id:
                return r["name"]
        return rule_id

    def _get_description(self, rule_id: str) -> str:
        for r in RULES:
            if r["id"] == rule_id:
                return r["description"]
        return ""


# Need base64 import


def scan_file(filepath: Path) -> list[ScanFinding]:
    """Quick scan function for compatibility."""
    scanner = SkillScanner()
    return scanner.scan_file(filepath)


def scan_directory(target: str) -> dict:
    """Compatibility wrapper returning Elliot's format."""
    scanner = SkillScanner()
    result = scanner.scan_path(target)
    return {
        "target": result.target,
        "scanner": result.scanner,
        "total_findings": len(result.findings),
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in result.findings],
    }