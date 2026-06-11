"""
Infostealer Intelligence Module — Find Evil Hackathon
Parses infostealer log formats and extracts credentials.
Based on Elliot Cybersecurity Lab's infostealer_intel
"""

import re
from abc import ABC, abstractmethod
from typing import Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

__all__ = [
    "InfostealerParser",
    "Credential",
    "ParserRegistry",
    "register_default_parsers",
    "RedLineParser",
    "LummaParser",
    "VidarParser",
    "RaccoonParser",
]


@dataclass
class Credential:
    """Normalized credential from infostealer logs."""

    credential_type: str
    value: str
    source_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    timestamp: Optional[str] = None
    source_stealer: str = "unknown"
    raw_line: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_stix_credential(self) -> dict[str, Any]:
        """Convert to STIX 2.1 Credential object."""
        return {
            "type": "credential",
            "spec_version": "2.1",
            "id": f"credential--{self.credential_type}-{hash(self.value)}",
            "created": self.timestamp or datetime.utcnow().isoformat() + "Z",
            "modified": self.timestamp or datetime.utcnow().isoformat() + "Z",
            "credential_type": self.credential_type,
            "value": self.value,
            "description": f"Extracted from {self.source_stealer} infostealer log",
            "external_references": [
                {
                    "source_name": "infostealer",
                    "description": f"{self.source_stealer} log format",
                    "url": self.source_url or "file://local",
                }
            ],
            "x_mitre_technique": "T1003.001"
            if self.credential_type in ["password", "login"]
            else "T1555",
        }


class InfostealerParser(ABC):
    """Base class for infostealer log parsers."""

    STEALER_NAME: str = "unknown"
    FILE_PATTERNS: list[str] = []

    def __init__(self):
        self.credentials: list[Credential] = []
        self.stats = {
            "total_lines": 0,
            "parsed_lines": 0,
            "credentials_found": 0,
            "errors": 0,
        }

    @abstractmethod
    def parse(self, content: str) -> list[Credential]:
        pass

    def parse_file(self, filepath: Path) -> list[Credential]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.parse(content)
        except Exception:
            self.stats["errors"] += 1
            return []

    def can_parse(self, filepath: Path) -> bool:
        if not self.FILE_PATTERNS:
            return False
        filename = filepath.name.lower()
        return any(re.search(pattern, filename, re.IGNORECASE) for pattern in self.FILE_PATTERNS)

    def _create_credential(self, cred_type: str, value: str, **kwargs) -> Credential:
        return Credential(
            credential_type=cred_type,
            value=value,
            source_stealer=self.STEALER_NAME,
            **kwargs,
        )

    def get_stats(self) -> dict[str, int]:
        return self.stats.copy()


class ParserRegistry:
    """Registry of all available infostealer parsers."""

    _parsers: list[InfostealerParser] = []

    @classmethod
    def register(cls, parser_class):
        cls._parsers.append(parser_class())

    @classmethod
    def get_all_parsers(cls) -> list[InfostealerParser]:
        return cls._parsers.copy()

    @classmethod
    def get_parser_for_file(cls, filepath: Path) -> Optional[InfostealerParser]:
        if not cls._parsers:
            register_default_parsers()
        for parser in cls._parsers:
            if parser.can_parse(filepath):
                return parser
        return None

    @classmethod
    def parse_with_all(cls, content: str) -> list[Credential]:
        all_creds = []
        for parser in cls._parsers:
            try:
                creds = parser.parse(content)
                all_creds.extend(creds)
            except Exception:
                pass
        return all_creds


def register_default_parsers():
    """Register all default parsers. Call explicitly."""
    for parser_class in [RedLineParser, LummaParser, VidarParser, RaccoonParser]:
        ParserRegistry.register(parser_class)


# =============================================================================
# Specific Parsers
# =============================================================================


class RedLineParser(InfostealerParser):
    """Parser for RedLine Stealer logs."""

    STEALER_NAME = "redline"
    FILE_PATTERNS = [r".*[Rr]ed[Ll]ine.*\.txt", r".*logs?\.txt", r".*passwords?\.txt"]

    def parse(self, content: str) -> list[Credential]:
        creds = []
        lines = content.split("\n")
        self.stats["total_lines"] = len(lines)

        for line_no, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Format: URL: https://example.com | Login: user | Password: pass
            url_match = re.search(r"URL:\s*(\S+)", line)
            login_match = re.search(r"Login:\s*(\S+)", line)
            pass_match = re.search(r"Password:\s*(\S+)", line)

            if url_match or login_match or pass_match:
                self.stats["parsed_lines"] += 1
                url = url_match.group(1) if url_match else None
                username = login_match.group(1) if login_match else None
                password = pass_match.group(1) if pass_match else None

                if url:
                    creds.append(
                        self._create_credential(
                            "url",
                            url,
                            source_url=url,
                            username=username,
                            password=password,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )
                if username:
                    creds.append(
                        self._create_credential(
                            "login",
                            username,
                            source_url=url,
                            password=password,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )
                if password:
                    creds.append(
                        self._create_credential(
                            "password",
                            password,
                            source_url=url,
                            username=username,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )

                self.stats["credentials_found"] += len(
                    [c for c in [url, username, password] if c]
                )

        return creds


class LummaParser(InfostealerParser):
    """Parser for Lumma Stealer logs."""

    STEALER_NAME = "lumma"
    FILE_PATTERNS = [r".*[Ll]umma.*\.txt", r".*logs?\.txt", r".*grabber.*\.txt"]

    def parse(self, content: str) -> list[Credential]:
        creds = []
        lines = content.split("\n")
        self.stats["total_lines"] = len(lines)

        for line_no, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Format: username: value | password: value | email: value | url: value
            for key in ["username", "password", "email", "url"]:
                pattern = rf"{key}:\s*(\S+)"
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    self.stats["parsed_lines"] += 1
                    value = match.group(1)
                    creds.append(
                        self._create_credential(
                            key,
                            value,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )
                    self.stats["credentials_found"] += 1

        return creds


class VidarParser(InfostealerParser):
    """Parser for Vidar Stealer logs."""

    STEALER_NAME = "vidar"
    FILE_PATTERNS = [r".*[Vv]idar.*\.txt", r".*logs?\.txt"]

    def parse(self, content: str) -> list[Credential]:
        creds = []
        lines = content.split("\n")
        self.stats["total_lines"] = len(lines)

        for line_no, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Format: Domain: value | User: value | Pass: value
            for key in ["Domain", "User", "Pass"]:
                pattern = rf"{key}:\s*(\S+)"
                match = re.search(pattern, line)
                if match:
                    self.stats["parsed_lines"] += 1
                    value = match.group(1)
                    cred_type = "domain" if key == "Domain" else "login" if key == "User" else "password"
                    creds.append(
                        self._create_credential(
                            cred_type,
                            value,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )
                    self.stats["credentials_found"] += 1

        return creds


class RaccoonParser(InfostealerParser):
    """Parser for Raccoon Stealer logs."""

    STEALER_NAME = "raccoon"
    FILE_PATTERNS = [r".*[Rr]accoon.*\.txt", r".*logs?\.txt", r".*autofill.*\.txt"]

    def parse(self, content: str) -> list[Credential]:
        creds = []
        lines = content.split("\n")
        self.stats["total_lines"] = len(lines)

        for line_no, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Format: url: value | login: value | password: value | autofill: value
            for key in ["url", "login", "password", "autofill"]:
                pattern = rf"{key}:\s*(\S+)"
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    self.stats["parsed_lines"] += 1
                    value = match.group(1)
                    creds.append(
                        self._create_credential(
                            key,
                            value,
                            raw_line=line,
                            line_number=line_no,
                        )
                    )
                    self.stats["credentials_found"] += 1

        return creds