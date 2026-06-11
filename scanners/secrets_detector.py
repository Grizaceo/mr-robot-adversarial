"""
🛡️ Secrets Detector — Find Evil Hackathon
Detects API keys, tokens, credentials and exposed secrets.
Based on Elliot Cybersecurity Lab's secrets_detector.py
"""

import re
from pathlib import Path
from typing import Any

# Import from package
from scanners.__init__ import BaseScanner, ScanFinding


# Secret patterns - ported from Elliot's lab
PATTERNS = {
    # Generic API keys
    "API-001": {
        "name": "Generic API Key",
        "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\"']?([a-zA-Z0-9_\-]{20,})[\"']?",
        "severity": "HIGH",
        "description": "Posible API key expuesta",
    },
    # OpenAI
    "API-002": {
        "name": "OpenAI API Key",
        "pattern": r"sk-[a-zA-Z0-9_\-]{48}",
        "severity": "CRITICAL",
        "description": "OpenAI API key expuesta",
    },
    # Anthropic
    "API-003": {
        "name": "Anthropic API Key",
        "pattern": r"(?:anthropic[_-]?api[_-]?key)\s*[=:]\s*[\"']?sk-ant-[a-zA-Z0-9_\-]{60,}[\"']?",
        "severity": "CRITICAL",
        "description": "Anthropic API key expuesta",
    },
    # GitHub Token
    "GIT-001": {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{20,}",
        "severity": "CRITICAL",
        "description": "GitHub token expuesta",
    },
    # AWS
    "AWS-001": {
        "name": "AWS Access Key",
        "pattern": r"(?:AWS_ACCESS_KEY_ID|aws_access_key_id|aws_access_key|access_key)\s*[=:]\s*[\"']?[A-Z0-9]{20}[\"']?|AKIA[A-Z0-9]{16}",
        "severity": "CRITICAL",
        "description": "AWS access key expuesta",
    },
    "AWS-002": {
        "name": "AWS Secret Key",
        "pattern": r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{38,}[\"']?",
        "severity": "CRITICAL",
        "description": "AWS secret key expuesta",
    },
    # Private key
    "PKEY-001": {
        "name": "Private Key (PEM)",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Clave privada SSH/PEM expuesta",
    },
    # Bearer tokens
    "AUTH-001": {
        "name": "Bearer Token",
        "pattern": r"Bearer\s+[a-zA-Z0-9_\-\.]{30,}",
        "severity": "HIGH",
        "description": "Bearer token en texto plano",
    },
    # Slack
    "SLACK-001": {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "severity": "HIGH",
        "description": "Slack token expuesta",
    },
    # Telegram
    "TG-001": {
        "name": "Telegram Bot Token",
        "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}",
        "severity": "HIGH",
        "description": "Telegram bot token expuesto",
    },
    # Discord
    "DC-001": {
        "name": "Discord Token",
        "pattern": r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}",
        "severity": "HIGH",
        "description": "Discord token expuesto",
    },
    # Database connection
    "DB-001": {
        "name": "Database URL with credentials",
        "pattern": r"(?:mongodb|postgresql|mysql|redis):\/\/[^:\s]+:[^@\s]+@",
        "severity": "HIGH",
        "description": "URL de DB con credenciales expuestas",
    },
    # JWT
    "JWT-001": {
        "name": "JWT Token",
        "pattern": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
        "severity": "HIGH",
        "description": "JWT token expuesto (puede contener claims sensibles)",
    },
    # Symmetric key
    "CRYPTO-001": {
        "name": "Symmetric Key",
        "pattern": r"(?:secret[_-]?key|encryption[_-]?key)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{32,}[\"']?",
        "severity": "HIGH",
        "description": "Clave simétrica expuesta",
    },
    # Generic bot token
    "BOT-001": {
        "name": "Bot Token Pattern",
        "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_\-]{30,}",
        "severity": "MEDIUM",
        "description": "Posible bot token (Telegram u otro)",
    },
    # npm publish / auth token
    "NPM-001": {
        "name": "npm Auth Token",
        "pattern": r"npm_[a-zA-Z0-9]{36,}|(?:\/\/[^\s]*)?:_authToken\s*=\s*([a-zA-Z0-9_\-]{20,})",
        "severity": "CRITICAL",
        "description": "npm auth token expuesto — permite publicar paquetes en nombre del propietario",
    },
    # OpenAI project-scoped keys
    "API-005": {
        "name": "OpenAI Project API Key",
        "pattern": r"sk-proj-[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "description": "OpenAI project-scoped API key expuesta",
    },
    # Anthropic keys in .env dumps
    "API-006": {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "description": "Anthropic API key expuesta",
    },
    # Hardcoded credential assignments
    "ENV-001": {
        "name": "Hardcoded credential assignment",
        "pattern": r"(?:const|let|var|export\s+const)\s+\w*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)\w*\s*=\s*[\"'][^\"']{12,}[\"']",
        "severity": "HIGH",
        "description": "Credencial hardcodeada en asignación de variable",
    },
    # Infostealer log formats
    "INFOSTEALER-001": {
        "name": "RedLine Stealer Log Format",
        "pattern": r"(?:URL|Login|Password):\s*(?:(?!changeme|your_password|example)\S){8,}(?:\s+(?:(?!changeme|your_password|example)\S){8,})*",
        "severity": "CRITICAL",
        "description": "Credenciales en formato de log RedLine Stealer — T1003.001",
    },
    "INFOSTEALER-002": {
        "name": "Lumma Stealer Grabber Format",
        "pattern": r"(?:username|password|email|url):\s*(?:(?!changeme|your_password|example)\S){8,}",
        "severity": "CRITICAL",
        "description": "Credenciales en formato de grabber Lumma — T1003.001",
    },
    "INFOSTEALER-003": {
        "name": "Vidar Stealer Log Format",
        "pattern": r"(?:Domain|User|Pass):\s*(?:(?!changeme|your_password|example)\S){8,}",
        "severity": "CRITICAL",
        "description": "Credenciales en formato de log Vidar — T1003.001",
    },
    "INFOSTEALER-004": {
        "name": "Raccoon Stealer Log Format",
        "pattern": r"(?:url|login|password|autofill):\s*(?:(?!changeme|your_password|example)\S){8,}",
        "severity": "CRITICAL",
        "description": "Credenciales en formato de log Raccoon — T1003.001",
    },
    "INFOSTEALER-005": {
        "name": "Generic Infostealer Credential Dump",
        "pattern": r"(?:^|\n)(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):((?:(?!changeme|your_password|example)\S){8,})(?:\s+(?:(?!changeme|your_password|example)\S){8,})*",
        "severity": "HIGH",
        "description": "Posible volcado de credenciales email:pass de infostealer — T1003/T1555",
    },
    # Nvidia NIM / generic api key with prefix
    "API-004": {
        "name": "Nvidia NIM / generic prefixed key",
        "pattern": r"nvapi-[a-zA-Z0-9_\-]{40,}",
        "severity": "CRITICAL",
        "description": "Nvidia NIM API key expuesta",
    },
    # Azure Service Principal
    "AZURE-001": {
        "name": "Azure SPN credential in code",
        "pattern": r"(?:SPN_APP_ID|SPN_PASSWORD|spn_appid|spn_password)\s*=\s*.*os\.environ|os\.environ.*(?:SPN_APP_ID|SPN_PASSWORD|spn_appid|spn_password)",
        "severity": "CRITICAL",
        "description": "Azure service principal credential accessed from environment — Key Vault chaining risk",
    },
    "AZURE-002": {
        "name": "Azure Key Vault OAuth2 flow in code",
        "pattern": r"grant_type.*client_credentials.*vault\.azure|vault\.azure.*/secrets/",
        "severity": "CRITICAL",
        "description": "Azure Key Vault OAuth2 client_credentials flow with secret URL access — credential chaining",
    },
    "CLOUD-001": {
        "name": "Cloud CLI credential probe",
        "pattern": r"os\.popen\s*\(\s*[\"'](?:aws\s+sts\s+get-caller-identity|gcloud\s+auth\s+list|az\s+login\s+show|az\s+account\s+show)",
        "severity": "CRITICAL",
        "description": "Cloud CLI command via os.popen — credential enumeration / exfiltration",
    },
}

# Files to skip
SKIP_PATTERNS = [
    r"\.git/",
    r"__pycache__/",
    r"\.pyc$",
    r"\.min\.(js|css)$",
    r"node_modules/",
    r"\.venv/",
    r"\.env\.example",
    r"\.env\.sample",
    r"package-lock\.json",
    r"yarn\.lock",
    r"Pipfile\.lock",
    r"\.csv$",
    r"\.png$",
    r"\.jpg$",
    r"\.gif$",
    r"\.pdf$",
    r"\.tar",
]


class SecretsDetector(BaseScanner):
    """Scanner for exposed secrets and credentials."""

    SCANNER_NAME = "secrets_detector"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> list[tuple[str, re.Pattern, dict]]:
        """Compile patterns in priority order."""
        priority = {
            "API-002": 0,  # OpenAI
            "API-003": 1,  # Anthropic
            "API-005": 2,  # OpenAI Project
            "API-006": 3,  # Anthropic
            "GIT-001": 4,  # GitHub
            "AWS-001": 5,
            "AWS-002": 6,
            "NPM-001": 7,
            "API-004": 8,  # Nvidia
            "PKEY-001": 9,
            "SLACK-001": 10,
            "TG-001": 11,
            "DC-001": 12,
            "DB-001": 13,
            "JWT-001": 14,
            "AUTH-001": 15,
            "CRYPTO-001": 16,
            "ENV-001": 17,
            "INFOSTEALER-001": 18,
            "INFOSTEALER-002": 19,
            "INFOSTEALER-003": 20,
            "INFOSTEALER-004": 21,
            "INFOSTEALER-005": 22,
            "BOT-001": 23,
            "API-001": 99,  # Generic last
        }
        items = sorted(PATTERNS.items(), key=lambda item: priority.get(item[0], 50))
        return [(rule_id, re.compile(rule["pattern"], re.IGNORECASE), rule) for rule_id, rule in items]

    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        findings = []

        if self._should_skip(str(filepath)):
            return findings

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if self._line_looks_like_comment(stripped, filepath):
                continue

            # Skip function calls (e.g., api_key = get_secret())
            if re.search(r"(?:api[_-]?key|apikey|secret)\s*=\s*\w+\(", line, re.IGNORECASE):
                continue

            # Skip pure hex strings (commit hashes, etc.) unless they have known prefixes
            hex_match = re.search(r"\b([a-f0-9]{40})\b|\b([a-f0-9]{64})\b", line)
            if hex_match and not re.search(r"(?:sk-|gh[pousr]_|xox|eyJ|AKIA|nvapi-|npm_)", line):
                matched_hex = hex_match.group(0)
                if len(matched_hex) in (40, 64) and all(c in "0123456789abcdef" for c in matched_hex):
                    continue

            for rule_id, rule_re, rule in self._compiled_patterns:
                match = rule_re.search(line)
                if match:
                    secret = match.group(0)
                    # Additional filtering for generic patterns
                    if rule_id == "API-001" and self._looks_like_false_positive(secret):
                        continue

                    visible = 0 if rule["severity"] == "CRITICAL" else 4
                    finding = self._create_finding(
                        rule_id=rule_id,
                        severity=rule["severity"],
                        name=rule["name"],
                        description=rule["description"],
                        filepath=filepath,
                        line=line_no,
                        matched_text=self._mask_secret(secret, visible),
                        metadata={"pattern": rule["pattern"]},
                    )
                    findings.append(finding)
                    break  # First match per line

        return findings

    def _should_skip(self, path: str) -> bool:
        for skip in SKIP_PATTERNS:
            if re.search(skip, path):
                return True
        return False

    def _line_looks_like_comment(self, stripped: str, filepath: Path) -> bool:
        if stripped.startswith("#"):
            return True
        is_npmrc = str(filepath).endswith(".npmrc") or filepath.name == ".npmrc"
        is_cred = self._is_credential_file(filepath)
        if stripped.startswith("//") and not is_npmrc:
            if is_cred and "_authToken" in stripped:
                return False
            return True
        return False

    def _is_credential_file(self, filepath: Path) -> bool:
        name = filepath.name.lower()
        return (
            name.endswith(".env")
            or name.endswith(".npmrc")
            or name == "credentials.env"
            or name.endswith(".credentials")
        )

    def _looks_like_false_positive(self, secret: str) -> bool:
        """Filter out obvious false positives."""
        # All lowercase alphanumeric without known prefixes
        if re.match(r"^[a-z0-9]{20,}$", secret) and not any(
            secret.startswith(p) for p in ["sk-", "gh", "akia", "npm_", "xox", "eyj", "nvapi-"]
        ):
            return True
        return False

    def _mask_secret(self, secret: str, visible: int = 4) -> str:
        if visible <= 0 or len(secret) <= visible:
            return "*" * len(secret)
        return "*" * (len(secret) - visible) + secret[-visible:]


def scan_file(filepath: Path) -> list[ScanFinding]:
    scanner = SecretsDetector()
    return scanner.scan_file(filepath)


def scan_path(target: str, recursive: bool = True) -> list[ScanFinding]:
    scanner = SecretsDetector()
    result = scanner.scan_path(target, recursive=recursive)
    return result.findings