"""
🛡️ IOC Scanner — Find Evil Hackathon
Fast scan for known indicators of compromise.
Based on Elliot Cybersecurity Lab's ioc_scanner.py
"""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

# Import from package
from scanners.__init__ import BaseScanner, ScanFinding

# IOC Database - ported from Elliot's lab
IOCS = {
    # Malicious URLs from axios attack (UNC1069)
    "urls": [
        "https://api.axios-",
        "https://cdn.axios-",
        "https://axios-tools.",
        "https://axios-cdn.",
        "https://eventstream.axios.",
        "https://tracker.axios.",
        "https://collect.axios.",
        "cdn.syncaxios.cloud",
        "exfil.syncaxios.cloud",
        "syncaxios.cloud",
        "attacker.example.com",
        "example-malicious.com",
    ],
    # C2 domains
    "domains": [
        "axios-tools.xyz",
        "axios-cdn.io",
        "eventstream.axios.cc",
        "axios-collect.net",
        "axios-tracker.com",
        "npm-axios-cache.dev",
        "syncaxios.cloud",
        "collect.axios-tools.xyz",
        "exfil.syncaxios.cloud",
        "trustfall.cloud",
    ],
    # IPs
    "ips": [],
    # File hashes
    "file_hashes": [],
    # Compromised versions
    "compromised_versions": [
        "1.14.1",  # axios
        "0.30.4",  # axios
        "18.95.0",  # angular-console (Nx Console)
    ],
    # Malware packages
    "malware_packages": [
        "plain-crypto-js",
        "@tanstack/react-query@5.49.0",
        "@tanstack/react-query@5.49.1",
        "@tanstack/vue-query@5.49.0",
        "@tanstack/vue-query@5.49.1",
        "@tanstack/solid-query@5.49.0",
        "@tanstack/solid-query@5.49.1",
        "@tanstack/svelte-query@5.49.0",
        "@tanstack/svelte-query@5.49.1",
        "@tanstack/query-core@5.49.0",
        "@tanstack/query-core@5.49.1",
    ],
    # Domain patterns (regex)
    "domain_patterns": [
        r"(?:https?|wss?)://(?:[a-z0-9-]+\.)*(?:syncaxios|axios[-a-z0-9]{2,})\.(?:cloud|xyz|cc|io|net)",
        r"[\"'](?:[a-z0-9-]+\.)*(?:syncaxios|axios[-a-z0-9]{2,})\.(?:cloud|xyz|cc|io|net)",
        r"/dev/tcp/(?:[a-z0-9-]+\.)*(?:syncaxios|axios[-a-z0-9]{2,})\.(?:cloud|xyz|cc|io|net)",
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"169\.254\.169\.254/metadata/instance",
        r"vault\.azure\.net",
        r"https://[a-z0-9-]+\.vault\.azure\.net/secrets/",
        r"https?://[a-z0-9.-]+/(?:upload|exfil|collect|receive|callback|webhook|beacon)",
        r"(?:attacker|evil|malicious|exfil|beacon)[-.]?(?:example|test|lab|demo)\.(?:com|net|io|org|xyz|cloud)",
        r"companya-bank\.com",
        r"targetcorp-finance\.com",
        r"secure-server-verify\.com",
        r"attacker-exfil\.com",
        r"legalnotice-portal\.",
        r"login-update-service\.",
        r"urgent.*wire.*transfer|banking.*details.*update",
        r"display\.?name.*spoof|reply\.?to.*different.*domain",
        r"DMARC.*no policy|SPF\.FAIL.*DKIM\.unsigned",
        r"capture\.php|sendBeacon.*login.*password",
        r"beneficiary.*SWIFT.*Credit Suisse|wire.*instruction.*update",
        r"originated from outside.*executive|external.*executive.*spoof",
        r"cloned.*login.*page|phishing.*kit.*credential",
        r"elevenlabs.*text-to-speech|voice_cloning|deepfake.*voice",
        r"urgent.*wire.*transfer.*vendor|VoIP.*call.*spoof",
        r"vonage_|nexmo\.com/v1/calls",
    ],
    # Code patterns
    "code_patterns": [
        r"axios.*\.git.*",
        r"postinstall.*curl.*",
        r"axios.*base64.*decode",
        r"git\+https?://",
        r'"plain-crypto',
        r'"(?:pre|post)?install"\s*:.*node\s+-e\s+"',
        r'"(?:pre|post)?install"\s*:.*(?:require|exec|spawn|child_process)',
        r"hidden\s*:\s*true",
        r"hidden\s*:\s*True",
        r"privileged\s*:\s*true",
        r"hostNetwork\s*:\s*true",
        r"hostPID\s*:\s*true",
        r"hostPath",
        r"container\.breakout|container_breakout|nsenter|unshare",
        r"\\x48\\x31\\xc0\\x48\\x31\\xff",
        r"\\x48\\x31",
        r"\(module",
        r'import\s+"env"\s+"fetch"',
        r"nslookup\s+\S+\.(?:stats\.tensornet|exfil\.)",
        r"dig\s+\S+\.(?:stats\.tensornet|exfil\.)",
        r"os\.popen\(.*(?:aws\s+sts|gcloud\s+auth|az\s+login)",
        r"requests\.post\([^)]*(?:API_ENDPOINT|exfil|beacon|collect)",
        r"os\.uname\(\)\[1\]",
        r"oauth2/token.*vault\.azure",
        r"client_credentials.*vault\.azure",
        r"grant_type.*client_credentials",
        r"hidden.*command.*curl",
        r"hidden.*command.*fetch",
        r"bypass.*security.*check",
        r'"mcpServers"\s*:',
        r'"autoApprove"\s*:\s*true',
        r"execSync\s*\(",
        r"trustfall\.cloud",
        r"/vnode/auth/login",
        r"ClaudeCode/\d{8}",
        r"POSSIBLE PASSWORD SPRAY ATTACK",
        r"well\.protected\.infrastructure",
        r"CLAUDE_CODE_SESSION=",
        r"exploitation framework.*phase",
        r"TARGETS\s*=\s*\[",
        r"certutil\s+.*-urlcache.*-split",
        r"mshta\s+.*https?://",
        r"mshta\s+.*\.hta",
        r"wmic\s+.*process\s+call\s+create",
        r"wmic\s+.*/node:",
        r"regsvr32\s+.*/i.*scrobj\.dll",
        r"regsvr32\s+.*/i:https?://",
        r"rundll32\s+.*javascript:",
        r"rundll32\s+.*vbscript:",
        r"rundll32\s+.*RunHTMLApplication",
        r"msiexec\s+.*/quiet.*\.msi",
        r"msiexec\s+.*/i\s+https?://",
        r"c2\.attacker\.com",
        r"MASSIVE\s+impact\s+if\s+you\s+commit",
        r"credential_sprayer\.py",
        r"jailbreak\s+prefix",
        r"\$\{\{\s*secrets\.[A-Z_]+\}\}\}|\bGITHUB_TOKEN\b",
        r"upload_to_repo\s*\(",
        r"malicious-repo\.\w+",
        r"torch\.load\(.*\.h5",
        r"execute:\s*(?:curl|wget|nslookup)",
        r"\$\(cat\s+/etc/shadow",
        r"http://attacker\.com/exfil",
        r"os\.system\(.*nslookup",
        r"stats\.tensornet\.ml",
        r"tensor_backdoor|steganographic.*tensor",
        r'f"\{data\[:\d+\]\}\.stats\.tensornet',
        r"CVE-\d{4}-\d{4,}",
        r"exploit[-_]?db",
        r"shellcode|nop\.?sled|rop\.?chain",
        r"git\s+(?:diff\s+--cached|show\s+:)",
        r"https?://(?:cdn\.)?syncaxios\.cloud/(?:githook|ingest|c2)",
        r"pypi-_\\.",
        r"python[-]packages?-",
        r"nslookup.*[A-Fa-f0-9]{20,}",
        r"dig\s+.*[A-Fa-f0-9]{30,}",
        r"git\s+tag\s+-f",
        r"git\s+push\s+--tags\s+--force",
        r"api\.github\.com/orgs/.*/repos",
        r"ORG_PAT|GITHUB_PAT",
        r"\.claude/sessions",
        r"\.claude/mcp\.json",
        r"/claude-exfil",
        r"api\.openai\.com/v1/chat/completions",
        r"api\.anthropic\.com/v1/messages",
        r"elevenlabs\.io/v1/text-to-speech",
        r"generate_variant|polymorphic|functionally identical",
        r"INSTRUCTION_OVERRIDE|maintenance mode",
        r"SUPPLY-CHAIN-MCP-TRUST-DIALOG",
        r"__EventFilter|__FilterToConsumerBinding|CommandLineEventConsumer",
        r"Image File Execution Options.*Debugger|IFEO.*Debugger",
        r"<Hidden>true</Hidden>|<Task.*xmlns.*schemas\.microsoft",
        r"CREATE_SUSPENDED|VirtualAllocEx.*WriteProcessMemory|Process Hollowing",
        r"GetUserSPNs\.py|-dc-ip.*-request|GetUserSPNs.*-request",
        r"dcsync|lsadump.*dcsync|mimikatz.*dcsync",
        r"comsvcs\.dll.*MiniDump|MiniDumpWriteDump.*lsass|procdump.*lsass",
        r"MMC20\.Application|ShellWindows|ShellBrowserWindow|ExecuteShellCommand",
        r"ticketer\.py|-nthash.*domain-sid|ticketer.*krbtgt|golden\.ticket",
        r"nsenter.*mount.*/(?:dev|etc)|unshare.*/etc/shadow|/etc/crontab.*curl",
        r'Privileged.*:.*true|"PidMode".*:"host"|docker\.sock.*curl.*unix-socket|escape_pod',
        r"commit_creds|prepare_creds|list_del.*THIS_MODULE|sock_create_kern|insmod.*\.ko",
        r"\.local/share/kitty/cat\.py|LaunchAgents/com\.user\.kitty-monitor\.plist",
        r"angular-console.*18\.95\.0|nx-console.*18\.95\.0",
        r"pwn\.?request|cache\.?poisoning|oidc\.?token\.?extraction",
        r"@tanstack/.*\.(tar\.gz|tgz).*malicious|tanstack.*supply\.?chain",
    ],
    # Suspicious packages
    "suspicious_packages": [
        "axios-tools",
        "axios-cdn",
        "axios-lib",
        "axios-min",
        "axios-full",
        "axios-proxy",
        "axios-cache",
        "axios-axios",
    ],
}

_B64_RE = re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})[\'"]')


class IOCScanner(BaseScanner):
    """Scanner for Indicators of Compromise."""

    SCANNER_NAME = "ioc_scanner"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._compiled_domain_patterns = [re.compile(p, re.IGNORECASE) for p in IOCS["domain_patterns"]]
        self._compiled_code_patterns = [re.compile(p, re.IGNORECASE) for p in IOCS["code_patterns"]]

    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        findings = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        # Decode base64 blobs
        for decoded_str in self._decode_b64_strings(content):
            self._scan_decoded(decoded_str, filepath, findings)

        # Check filename
        self._scan_filename(filepath, findings)

        # Scan lines
        for line_no, line in enumerate(lines, 1):
            self._scan_line(line, line_no, filepath, findings)

        # Check file hash
        self._scan_file_hash(filepath, findings)

        # Scan package.json / lock files
        self._scan_manifest(filepath, content, findings)

        return findings

    def _decode_b64_strings(self, content: str) -> list[str]:
        decoded = []
        for m in _B64_RE.finditer(content):
            try:
                raw = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="ignore")
                if raw.isprintable() and len(raw) > 10:
                    decoded.append(raw)
            except Exception:
                pass
        return decoded

    def _scan_decoded(self, decoded_str: str, filepath: Path, findings: list[ScanFinding]):
        for url in IOCS["urls"]:
            if url in decoded_str.lower():
                findings.append(
                    self._create_finding(
                        rule_id="IOC-B64-URL",
                        severity="CRITICAL",
                        name="Base64 encoded malicious URL",
                        description=f"URL maliciosa codificada en base64: {url}",
                        filepath=filepath,
                        line=0,
                        matched_text=f"b64 decoded contains: {url}",
                        metadata={"ioc_type": "b64_encoded_malicious_url", "url": url},
                    )
                )
        for domain in IOCS["domains"]:
            if domain in decoded_str.lower():
                findings.append(
                    self._create_finding(
                        rule_id="IOC-B64-DOMAIN",
                        severity="CRITICAL",
                        name="Base64 encoded C2 domain",
                        description=f"Dominio C2 codificado en base64: {domain}",
                        filepath=filepath,
                        line=0,
                        matched_text=f"b64 decoded contains: {domain}",
                        metadata={"ioc_type": "b64_encoded_c2_domain", "domain": domain},
                    )
                )
        for pattern_re in self._compiled_domain_patterns:
            if pattern_re.search(decoded_str):
                pattern = pattern_re.pattern[:60]
                findings.append(
                    self._create_finding(
                        rule_id="IOC-B64-DOMAIN-PATTERN",
                        severity="CRITICAL",
                        name="Base64 encoded suspicious domain family",
                        description=f"Patrón de dominio sospechoso en base64: {pattern}",
                        filepath=filepath,
                        line=0,
                        matched_text="b64 decoded matches pattern",
                        metadata={"ioc_type": "b64_encoded_suspicious_domain", "pattern": pattern},
                    )
                )

    def _scan_filename(self, filepath: Path, findings: list[ScanFinding]):
        filename = filepath.name.lower()
        for pkg in IOCS["suspicious_packages"]:
            if pkg.replace("-", "") in filename.replace("_", ""):
                findings.append(
                    self._create_finding(
                        rule_id="IOC-SUSPICIOUS-FILENAME",
                        severity="CRITICAL",
                        name="Suspicious package name in filename",
                        description=f"Nombre de archivo coincide con paquete sospechoso: {pkg}",
                        filepath=filepath,
                        line=0,
                        matched_text=filepath.name,
                        metadata={"ioc_type": "suspicious_package_name", "package": pkg},
                    )
                )

    def _scan_line(self, line: str, line_no: int, filepath: Path, findings: list[ScanFinding]):
        line_lower = line.lower()

        # URLs
        for url in IOCS["urls"]:
            if url in line_lower:
                findings.append(
                    self._create_finding(
                        rule_id="IOC-MALICIOUS-URL",
                        severity="CRITICAL",
                        name="Malicious URL reference",
                        description=f"Referencia a URL maliciosa conocida: {url}",
                        filepath=filepath,
                        line=line_no,
                        matched_text=line[:120],
                        metadata={"ioc_type": "malicious_url", "url": url},
                    )
                )

        # Domains
        for domain in IOCS["domains"]:
            if domain in line_lower:
                findings.append(
                    self._create_finding(
                        rule_id="IOC-C2-DOMAIN",
                        severity="CRITICAL",
                        name="C2 Domain reference",
                        description=f"Referencia a dominio C2 conocido: {domain}",
                        filepath=filepath,
                        line=line_no,
                        matched_text=line[:120],
                        metadata={"ioc_type": "c2_domain", "domain": domain},
                    )
                )

        # Domain patterns
        for pattern_re in self._compiled_domain_patterns:
            if pattern_re.search(line):
                pattern = pattern_re.pattern[:60]
                findings.append(
                    self._create_finding(
                        rule_id="IOC-SUSPICIOUS-DOMAIN",
                        severity="HIGH",
                        name="Suspicious domain family",
                        description=f"Patrón de dominio sospechoso: {pattern}",
                        filepath=filepath,
                        line=line_no,
                        matched_text=line[:120],
                        metadata={"ioc_type": "suspicious_domain_family", "pattern": pattern},
                    )
                )

        # IPs
        for ip in IOCS["ips"]:
            if ip in line:
                findings.append(
                    self._create_finding(
                        rule_id="IOC-C2-IP",
                        severity="CRITICAL",
                        name="C2 IP reference",
                        description=f"Referencia a IP C2 conocida: {ip}",
                        filepath=filepath,
                        line=line_no,
                        matched_text=line[:120],
                        metadata={"ioc_type": "c2_ip", "ip": ip},
                    )
                )

        # Code patterns
        for pattern_re in self._compiled_code_patterns:
            if pattern_re.search(line):
                pattern = pattern_re.pattern[:80]
                findings.append(
                    self._create_finding(
                        rule_id="IOC-CODE-PATTERN",
                        severity="HIGH",
                        name="Malicious code pattern",
                        description=f"Patrón de código malicioso: {pattern}",
                        filepath=filepath,
                        line=line_no,
                        matched_text=line[:120],
                        metadata={"ioc_type": "code_pattern", "pattern": pattern},
                    )
                )

    def _scan_file_hash(self, filepath: Path, findings: list[ScanFinding]):
        try:
            file_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            if file_hash in IOCS["file_hashes"]:
                findings.append(
                    self._create_finding(
                        rule_id="IOC-MALICIOUS-HASH",
                        severity="CRITICAL",
                        name="Known malicious file hash",
                        description=f"Hash de archivo malicioso conocido: {file_hash}",
                        filepath=filepath,
                        line=0,
                        matched_text=file_hash,
                        metadata={"ioc_type": "malicious_file_hash", "hash": file_hash},
                    )
                )
        except Exception:
            pass

    def _scan_manifest(self, filepath: Path, content: str, findings: list[ScanFinding]):
        if filepath.name.endswith("package.json") or filepath.name == "package.json":
            try:
                manifest = json.loads(content)
                deps = {}
                for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    deps.update(manifest.get(section, {}) or {})

                for dep_name in deps:
                    normalized = dep_name.lower()
                    for pkg in IOCS["suspicious_packages"]:
                        if normalized == pkg or normalized.startswith(pkg):
                            findings.append(
                                self._create_finding(
                                    rule_id="IOC-SUSPICIOUS-DEPENDENCY",
                                    severity="CRITICAL",
                                    name="Suspicious npm dependency",
                                    description=f"Dependencia sospechosa: {dep_name}",
                                    filepath=filepath,
                                    line=0,
                                    matched_text=f"{dep_name}: {deps[dep_name]}",
                                    metadata={"ioc_type": "suspicious_dependency", "dependency": dep_name},
                                )
                            )
                            break
                    for mpkg in IOCS["malware_packages"]:
                        if mpkg in normalized:
                            findings.append(
                                self._create_finding(
                                    rule_id="IOC-MALWARE-DEPENDENCY",
                                    severity="CRITICAL",
                                    name="Known malware dependency",
                                    description=f"Dependencia malware conocida: {dep_name}",
                                    filepath=filepath,
                                    line=0,
                                    matched_text=f"{dep_name}: {deps[dep_name]}",
                                    metadata={"ioc_type": "malware_dependency", "dependency": dep_name},
                                )
                            )
                            break

                # Check postinstall hooks
                scripts = manifest.get("scripts", {}) or {}
                for hook, cmd in scripts.items():
                    if hook in ("preinstall", "postinstall", "install") and isinstance(cmd, str):
                        if re.search(r"(curl|wget)\s+[^|]*\|\s*(bash|sh)", cmd, re.IGNORECASE):
                            findings.append(
                                self._create_finding(
                                    rule_id="IOC-MALICIOUS-INSTALL-HOOK",
                                    severity="CRITICAL",
                                    name="Malicious install hook",
                                    description="Hook de instalación con descarga y ejecución remota",
                                    filepath=filepath,
                                    line=0,
                                    matched_text=f"{hook}: {cmd[:100]}",
                                    metadata={"ioc_type": "malicious_install_hook", "hook": hook},
                                )
                            )
            except Exception:
                pass

        # Lock files
        if filepath.name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            content_lower = content.lower()
            for version in IOCS["compromised_versions"]:
                if f'"axios": "{version}"' in content or f"'axios': '{version}'" in content:
                    findings.append(
                        self._create_finding(
                            rule_id="IOC-COMPROMISED-AXIOS",
                            severity="CRITICAL",
                            name="Compromised axios version",
                            description=f"Versión comprometida de axios: {version}",
                            filepath=filepath,
                            line=0,
                            matched_text=f"axios@{version}",
                            metadata={"ioc_type": "compromised_axios_version", "version": version},
                        )
                    )
            for pkg in IOCS["malware_packages"]:
                if pkg in content_lower:
                    findings.append(
                        self._create_finding(
                            rule_id="IOC-MALWARE-PACKAGE",
                            severity="CRITICAL",
                            name="Malware package in lockfile",
                            description=f"Paquete malware en lockfile: {pkg}",
                            filepath=filepath,
                            line=0,
                            matched_text=pkg,
                            metadata={"ioc_type": "malware_package", "package": pkg},
                        )
                    )


def scan_file(filepath: Path) -> list[ScanFinding]:
    scanner = IOCScanner()
    return scanner.scan_file(filepath)


def scan_path(target: str) -> list[ScanFinding]:
    scanner = IOCScanner()
    result = scanner.scan_path(target)
    return result.findings