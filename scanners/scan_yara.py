"""
🛡️ YARA Scanner — Find Evil Hackathon
Wrapper for YARA rules (nhi_tokens.yar + davi_malware_rules.yar)
Based on Elliot Cybersecurity Lab's scan_yara.py
"""

import yara
from pathlib import Path
from typing import Any

# Import from package
from scanners.__init__ import BaseScanner, ScanFinding, ScanResult


TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".sh",
    ".bash",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".mjs",
    ".cjs",
    ".npmrc",
    ".env",
    ".toml",
    ".cfg",
    ".ini",
    ".conf",
    ".tf",
    ".hcl",
    ".rb",
    ".gemspec",
    ".rakefile",
    ".xml",
    ".php",
    ".pth",
    ".go",
    ".rs",
    ".java",
    ".gradle",
    ".groovy",
    ".kt",
    ".wasm",
    ".log",
    ".h5",
    ".c",
    ".ps1",
    ".bat",
    ".xml",
    ".psm1",
    ".vbs",
    ".hta",
    ".sct",
    ".docm",
    ".eml",
    ".jsonl",
    ".zip",
}

SCAN_FILENAMES = {
    ".npmrc",
    ".env",
    ".envrc",
    ".netrc",
    ".gitconfig",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "requirements.txt",
    "Jenkinsfile",
    "Podfile",
    "Gemfile",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}


class YaraScanner(BaseScanner):
    """YARA-based malware scanner."""

    SCANNER_NAME = "yara_scanner"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.rules_path = config.get("rules_path") if config else None
        self._rules = None

    def _compile_rules(self):
        """Compile YARA rules from configured paths."""
        if self._rules is not None:
            return self._rules

        rules_paths = []
        # Default rules in our repo
        base = Path(__file__).parent / "rules" / "yara"
        if base.exists():
            for f in base.glob("*.yar"):
                rules_paths.append(str(f))

        # Custom path from config
        if self.rules_path:
            p = Path(self.rules_path)
            if p.is_file():
                rules_paths.append(str(p))
            elif p.is_dir():
                rules_paths.extend(str(f) for f in p.glob("*.yar"))

        if not rules_paths:
            self.logger.warning("No YARA rules found")
            return None

        try:
            self._rules = yara.compile(filepaths={f"rules_{i}": p for i, p in enumerate(rules_paths)})
            self.logger.info(f"Compiled YARA rules from {len(rules_paths)} file(s)")
        except yara.SyntaxError as e:
            self.logger.error(f"YARA syntax error: {e}")
            self._rules = None
        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            self._rules = None

        return self._rules

    def _list_files(self, path_obj: Path) -> list[Path]:
        if path_obj.is_file():
            return [path_obj]
        if path_obj.is_dir():
            files = []
            for f in path_obj.rglob("*"):
                if f.is_file() and not any(part in SKIP_DIRS for part in f.parts):
                    if f.suffix.lower() in TEXT_SUFFIXES or f.name in SCAN_FILENAMES:
                        files.append(f)
            return files
        return []

    def _flatten_match(self, file_path: Path, match) -> list[ScanFinding]:
        findings = []
        for string_match in match.strings:
            identifier = getattr(string_match, "identifier", "$unknown")
            instances = getattr(string_match, "instances", []) or []
            if not instances:
                findings.append(
                    self._create_finding(
                        rule_id=match.rule,
                        severity="HIGH",  # Default, can be enhanced from rule meta
                        name=f"YARA match: {identifier}",
                        description=f"YARA rule {match.rule} matched",
                        filepath=file_path,
                        line=0,
                        matched_text="",
                        metadata={"yara_rule": match.rule, "identifier": identifier},
                    )
                )
                continue

            for instance in instances:
                content = getattr(instance, "matched_data", b"")
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="replace")
                findings.append(
                    self._create_finding(
                        rule_id=match.rule,
                        severity="HIGH",
                        name=f"YARA match: {identifier}",
                        description=f"YARA rule {match.rule} matched",
                        filepath=file_path,
                        line=0,
                        matched_text=str(content)[:120],
                        metadata={"yara_rule": match.rule, "identifier": identifier, "offset": hex(getattr(instance, "offset", 0))},
                    )
                )
        return findings

    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        rules = self._compile_rules()
        if not rules:
            return []

        findings = []
        try:
            file_matches = rules.match(str(filepath))
            for match in file_matches:
                findings.extend(self._flatten_match(filepath, match))
        except Exception as e:
            self.logger.debug(f"YARA scan error for {filepath}: {e}")

        return findings

    def scan_path(self, target: str, recursive: bool = True) -> ScanResult:
        """Override to add YARA-specific logic."""
        import time

        start = time.perf_counter()
        rules = self._compile_rules()
        if not rules:
            return ScanResult(
                scanner=self.SCANNER_NAME,
                target=target,
                findings=[],
                files_scanned=0,
                errors=["No YARA rules compiled"],
                scan_duration_ms=0,
            )

        target_path = Path(target)
        files = self._list_files(target_path)
        if not files:
            return ScanResult(
                scanner=self.SCANNER_NAME,
                target=target,
                findings=[],
                files_scanned=0,
                errors=[f"No scannable files found in {target}"],
                scan_duration_ms=0,
            )

        findings = []
        errors = []

        for f in files:
            try:
                file_matches = rules.match(str(f))
                for match in file_matches:
                    findings.extend(self._flatten_match(f, match))
            except Exception as e:
                errors.append(f"{f}: {e}")

        duration_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            scanner=self.SCANNER_NAME,
            target=str(target),
            findings=findings,
            files_scanned=len(files),
            errors=errors,
            scan_duration_ms=duration_ms,
        )


def scan_file(filepath: Path, rules_path: str | None = None) -> list[ScanFinding]:
    config = {"rules_path": rules_path} if rules_path else {}
    scanner = YaraScanner(config)
    return scanner.scan_file(filepath)


def scan_path(target: str, rules_path: str | None = None) -> ScanResult:
    config = {"rules_path": rules_path} if rules_path else {}
    scanner = YaraScanner(config)
    return scanner.scan_path(target)