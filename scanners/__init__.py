"""
Scanner Base Classes — Find Evil Hackathon
Common interfaces and utilities for all scanners.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("find-evil.scanners")


@dataclass
class ScanFinding:
    """A single finding from a scanner."""

    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    name: str
    description: str
    file: str
    line: int
    matched_text: str
    scanner: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "name": self.name,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "matched_text": self.matched_text,
            "scanner": self.scanner,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""

    scanner: str
    target: str
    findings: list[ScanFinding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "total_findings": len(self.findings),
            "files_scanned": self.files_scanned,
            "errors": self.errors,
            "scan_duration_ms": self.scan_duration_ms,
            "findings": [f.to_dict() for f in self.findings],
        }


class BaseScanner(ABC):
    """Base class for all scanners."""

    SCANNER_NAME: str = "base"
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"find-evil.scanners.{self.SCANNER_NAME}")

    @abstractmethod
    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        """Scan a single file and return findings."""
        pass

    def scan_path(self, target: str, recursive: bool = True) -> ScanResult:
        """Scan a file or directory."""
        import time

        start = time.perf_counter()
        target_path = Path(target)
        files = []
        errors = []

        if target_path.is_file():
            files = [target_path]
        elif target_path.is_dir():
            if recursive:
                files = [f for f in target_path.rglob("*") if f.is_file()]
            else:
                files = [f for f in target_path.glob("*") if f.is_file()]
        else:
            errors.append(f"Target not found: {target}")

        findings = []
        for f in files:
            try:
                file_findings = self.scan_file(f)
                findings.extend(file_findings)
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

    def _create_finding(
        self,
        rule_id: str,
        severity: str,
        name: str,
        description: str,
        filepath: Path,
        line: int,
        matched_text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ScanFinding:
        return ScanFinding(
            rule_id=rule_id,
            severity=severity,
            name=name,
            description=description,
            file=str(filepath),
            line=line,
            matched_text=matched_text,
            scanner=self.SCANNER_NAME,
            metadata=metadata or {},
        )