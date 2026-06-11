"""
Non-Human Identity (NHI) Governance Module — Find Evil Hackathon
Discovers, lifecycle-scans, and risk-scores NHIs from local config files.
Based on Elliot Cybersecurity Lab's nhi_governance.py
"""

import re
import json
import hashlib
import time
import logging
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

# Import from package
from scanners.__init__ import BaseScanner, ScanFinding, ScanResult

logger = logging.getLogger("find-evil.scanners.nhi_governance")


@dataclass
class NHIIdentity:
    """A discovered non-human identity."""

    provider: str
    identity_type: str
    identifier: str
    name: str
    source_file: str
    permissions: list[str] = field(default_factory=list)
    owner: Optional[str] = None
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    rotation_period_days: Optional[int] = None
    is_active: bool = True
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NHIRisk:
    identity_id: str
    risk_score: float
    risk_level: str
    factors: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Discovery paths
DISCOVERY_PATHS = {
    "aws": ["~/.aws/credentials", "~/.aws/config"],
    "gcp": ["~/.config/gcloud/application_default_credentials.json", "~/.config/gcloud/credentials.db"],
    "azure": ["~/.azure/azureProfile.json", "~/.azure/accessTokens.json", "~/.azure/msal_token_cache.json"],
    "github": [".env", ".env.local", ".env.production", ".github/workflows/*.yml"],
    "k8s": ["~/.kube/config", "~/.kube/config-*"],
    "docker": ["~/.docker/config.json"],
}

# NHI Patterns
NHI_PATTERNS = {
    "github_pat": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
    "github_app": re.compile(r"(?:ghs|ghr)_[A-Za-z0-9_]{36,}"),
    "gitlab_token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "aws_key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "gcp_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "generic_token": re.compile(r"(?:export\s+)?(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*[=:]\s*[\"']?([A-Za-z0-9_\-\.]{16,})[\"']?"),
}


class NHIDiscovery:
    """Discover NHIs from config files on the local filesystem."""

    def __init__(self, search_paths: list[Path] | None = None):
        self.search_paths = search_paths or [Path.cwd()]
        self.identities: list[NHIIdentity] = []
        self._discovered_sources: set[str] = set()

    def discover_all(self) -> list[NHIIdentity]:
        self.identities = []
        self._discover_from_aws()
        self._discover_from_gcp()
        self._discover_from_azure()
        self._discover_from_github_actions()
        self._discover_from_k8s()
        self._discover_from_docker()
        self._discover_from_env_files()
        self._discover_from_patterns()
        logger.info(f"Discovered {len(self.identities)} NHIs")
        return self.identities

    def _discover_from_aws(self):
        aws_creds = Path("~/.aws/credentials").expanduser()
        aws_config = Path("~/.aws/config").expanduser()  # noqa: F841

        if aws_creds.exists():
            try:
                content = aws_creds.read_text()
                profiles = re.findall(r"\[([^\]]+)\]", content)
                for profile in profiles:
                    if profile == "default":
                        continue
                    role_match = re.search(rf"\[{re.escape(profile)}\].*?role_arn\s*=\s*(\S+)", content, re.DOTALL)
                    src_key = f"aws:{profile}"
                    if src_key not in self._discovered_sources:
                        self._discovered_sources.add(src_key)
                        self.identities.append(
                            NHIIdentity(
                                provider="aws",
                                identity_type="iam_role" if role_match else "iam_user",
                                identifier=role_match.group(1) if role_match else f"arn:aws:iam:::user/{profile}",
                                name=f"AWS Profile: {profile}",
                                source_file=str(aws_creds),
                                permissions=["sts:AssumeRole"] if role_match else [],
                                tags=["cloud", "aws"],
                            )
                        )
            except Exception as e:
                logger.debug(f"AWS discovery error: {e}")

    def _discover_from_gcp(self):
        gcp_adc = Path("~/.config/gcloud/application_default_credentials.json").expanduser()
        if gcp_adc.exists():
            try:
                data = json.loads(gcp_adc.read_text())
                client_email = data.get("client_email", "unknown")
                self.identities.append(
                    NHIIdentity(
                        provider="gcp",
                        identity_type="service_account",
                        identifier=client_email,
                        name=f"GCP SA: {client_email}",
                        source_file=str(gcp_adc),
                        tags=["cloud", "gcp"],
                    )
                )
            except Exception as e:
                logger.debug(f"GCP ADC discovery error: {e}")

        for base in self.search_paths:
            for sa_key in base.rglob("*service-account*.json"):
                if sa_key.exists():
                    try:
                        data = json.loads(sa_key.read_text())
                        self.identities.append(
                            NHIIdentity(
                                provider="gcp",
                                identity_type="service_account",
                                identifier=data.get("client_email", "unknown"),
                                name=f"GCP SA Key: {data.get('client_email', 'unknown')}",
                                source_file=str(sa_key),
                                tags=["cloud", "gcp", "key_file"],
                            )
                        )
                    except Exception:
                        pass

    def _discover_from_azure(self):
        az_profile = Path("~/.azure/azureProfile.json").expanduser()
        if az_profile.exists():
            try:
                data = json.loads(az_profile.read_text())
                subscriptions = data.get("subscriptions", [])
                for sub in subscriptions:
                    tenant = sub.get("tenantId", "unknown")
                    self.identities.append(
                        NHIIdentity(
                            provider="azure",
                            identity_type="app_registration",
                            identifier=f"tenant:{tenant}",
                            name=f"Azure Tenant: {tenant}",
                            source_file=str(az_profile),
                            tags=["cloud", "azure", "entra_id"],
                        )
                    )
            except Exception as e:
                logger.debug(f"Azure discovery error: {e}")

    def _discover_from_github_actions(self):
        for base in self.search_paths:
            for wf in base.rglob(".github/workflows/*.yml"):
                if wf.exists():
                    try:
                        content = wf.read_text()
                        if "GITHUB_TOKEN" in content:
                            self.identities.append(
                                NHIIdentity(
                                    provider="github",
                                    identity_type="token",
                                    identifier=f"GITHUB_TOKEN in {wf.name}",
                                    name=f"GitHub Actions Token: {wf.name}",
                                    source_file=str(wf),
                                    permissions=["contents:read", "contents:write"],
                                    tags=["ci", "github_actions", "token"],
                                )
                            )
                        for match in NHI_PATTERNS["github_pat"].finditer(content):
                            token = match.group()
                            self.identities.append(
                                NHIIdentity(
                                    provider="github",
                                    identity_type="pat",
                                    identifier=token[:12] + "...",
                                    name=f"GitHub PAT (prefix: {token[:4]}...)",
                                    source_file=str(wf),
                                    tags=["ci", "github", "pat"],
                                )
                            )
                    except Exception:
                        pass

    def _discover_from_k8s(self):
        kubeconfig = Path("~/.kube/config").expanduser()
        if kubeconfig.exists():
            try:
                import yaml

                data = yaml.safe_load(kubeconfig.read_text())
                contexts = data.get("contexts", [])
                for ctx in contexts:
                    ctx_name = ctx.get("name", "unknown")
                    user = ctx.get("context", {}).get("user", "unknown")
                    users = {u.get("name"): u.get("user", {}) for u in data.get("users", [])}
                    user_info = users.get(user, {})
                    if user_info.get("token") or user_info.get("exec"):
                        src_key = f"k8s:{ctx_name}:{user}"
                        if src_key not in self._discovered_sources:
                            self._discovered_sources.add(src_key)
                            self.identities.append(
                                NHIIdentity(
                                    provider="k8s",
                                    identity_type="sa",
                                    identifier=f"context:{ctx_name}/user:{user}",
                                    name=f"K8s SA: {user} ({ctx_name})",
                                    source_file=str(kubeconfig),
                                    tags=["k8s", "service_account"],
                                )
                            )
            except ImportError:
                content = kubeconfig.read_text()
                for match in re.finditer(r"users:\s*\n\s*- name:\s+(\S+)", content):
                    user = match.group(1)
                    self.identities.append(
                        NHIIdentity(
                            provider="k8s",
                            identity_type="sa",
                            identifier=f"user:{user}",
                            name=f"K8s User: {user}",
                            source_file=str(kubeconfig),
                            tags=["k8s", "service_account"],
                        )
                    )
            except Exception as e:
                logger.debug(f"K8s discovery error: {e}")

    def _discover_from_docker(self):
        docker_config = Path("~/.docker/config.json").expanduser()
        if docker_config.exists():
            try:
                data = json.loads(docker_config.read_text())
                auths = data.get("auths", {})
                for registry, creds in auths.items():
                    if registry not in self._discovered_sources:
                        self._discovered_sources.add(registry)
                        self.identities.append(
                            NHIIdentity(
                                provider="docker",
                                identity_type="registry_cred",
                                identifier=registry,
                                name=f"Docker Registry: {registry}",
                                source_file=str(docker_config),
                                tags=["docker", "registry"],
                            )
                        )
                creds_store = data.get("credsStore")
                if creds_store:
                    self.identities.append(
                        NHIIdentity(
                            provider="docker",
                            identity_type="credential_store",
                            identifier=creds_store,
                            name=f"Docker Cred Store: {creds_store}",
                            source_file=str(docker_config),
                            tags=["docker", "credential_store"],
                        )
                    )
            except Exception as e:
                logger.debug(f"Docker discovery error: {e}")

    def _discover_from_env_files(self):
        for base in self.search_paths:
            for env_file in base.rglob(".env*"):
                if env_file.is_file() and ".git" not in str(env_file):
                    try:
                        content = env_file.read_text()
                        for line in content.split("\n"):
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            match = re.match(r"(export\s+)?(?P<key>\w+)\s*[=:]\s*[\"']?(?P<value>[^\"'\s#]+)", line)
                            if match:
                                key = match.group("key")
                                nhi_keywords = [
                                    "TOKEN",
                                    "SECRET",
                                    "KEY",
                                    "PASSWORD",
                                    "API",
                                    "CLIENT_ID",
                                    "CLIENT_SECRET",
                                    "ACCESS_KEY",
                                    "PRIVATE_KEY",
                                ]
                                if any(kw in key.upper() for kw in nhi_keywords):
                                    src_key = f"env:{key}@{env_file}"
                                    if src_key not in self._discovered_sources:
                                        self._discovered_sources.add(src_key)
                                        self.identities.append(
                                            NHIIdentity(
                                                provider="generic",
                                                identity_type="token",
                                                identifier=f"{key} in {env_file.name}",
                                                name=f"Env Secret: {key}",
                                                source_file=str(env_file),
                                                tags=["env", "secret", key.lower()],
                                            )
                                        )
                    except Exception:
                        pass

    def _discover_from_patterns(self):
        globs = [
            "*.env",
            "*.env.*",
            "*credentials*",
            "*cred*",
            "*secrets*",
            "*tokens*",
            "*keys*",
            "*password*",
            "*secret*",
            "config.json",
            ".env",
            ".env.*",
        ]

        seen_tokens: set[str] = set()
        for base in self.search_paths:
            for pattern in globs:
                for f in base.rglob(pattern):
                    if f.is_file() and ".git" not in str(f) and "node_modules" not in str(f):
                        src = str(f)
                        if src in self._discovered_sources:
                            continue
                        try:
                            content = f.read_text(errors="replace")
                            for name, pattern_re in NHI_PATTERNS.items():
                                for match in pattern_re.finditer(content):
                                    token_hash = hashlib.sha256(match.group().encode()).hexdigest()[:12]
                                    if token_hash in seen_tokens:
                                        continue
                                    seen_tokens.add(token_hash)
                                    self.identities.append(
                                        NHIIdentity(
                                            provider={
                                                "github_pat": "github",
                                                "github_app": "github",
                                                "gitlab_token": "gitlab",
                                                "aws_key": "aws",
                                                "gcp_key": "gcp",
                                            }.get(name, "generic"),
                                            identity_type={
                                                "github_pat": "pat",
                                                "github_app": "app_token",
                                                "gitlab_token": "pat",
                                                "aws_key": "access_key",
                                                "gcp_key": "api_key",
                                            }.get(name, "token"),
                                            identifier=f"{name}:{token_hash}",
                                            name=f"{name.replace('_', ' ').title()} in {f.name}",
                                            source_file=src,
                                            tags=["pattern_discovery", name],
                                        )
                                    )
                        except Exception:
                            pass


class NHILifecycleScanner:
    """Check lifecycle status of discovered NHIs."""

    STALE_DAYS = 90
    EXPIRY_WINDOW = 30
    MAX_ROTATION = 365

    def scan(self, identities: list[NHIIdentity]) -> list[NHIIdentity]:
        for identity in identities:
            src = Path(identity.source_file)
            if src.exists():
                mtime = src.stat().st_mtime
                age_days = (time.time() - mtime) / 86400
                if age_days > self.STALE_DAYS:
                    identity.last_used = datetime.fromtimestamp(mtime).isoformat()
                    identity.tags.append("stale")

            if src.exists():
                age_days = (time.time() - src.stat().st_mtime) / 86400
                identity.rotation_period_days = int(age_days)
                if age_days > self.MAX_ROTATION:
                    identity.tags.append("overdue_rotation")

            if identity.provider == "gcp" and identity.source_file.endswith(".json"):
                try:
                    data = json.loads(Path(identity.source_file).read_text())
                    if "valid_after" in data:
                        identity.created_at = data["valid_after"]
                    if "valid_before" in data:
                        identity.expires_at = data["valid_before"]
                except Exception:
                    pass

        return identities


class NHIRiskScorer:
    """Risk score NHIs based on lifecycle, permissions, and ownership."""

    def score(self, identities: list[NHIIdentity]) -> list[NHIRisk]:
        risks = []
        for identity in identities:
            factors = []
            score = 0.0

            if not identity.owner:
                factors.append("no_owner")
                score += 0.3

            if "stale" in identity.tags:
                factors.append("stale")
                score += 0.2

            if "overdue_rotation" in identity.tags:
                factors.append("overdue_rotation")
                score += 0.2

            broad_perms = [p for p in identity.permissions if "*" in p]
            if broad_perms:
                factors.append("broad_permissions")
                score += 0.15

            if identity.provider in ("aws", "gcp", "azure") and identity.identity_type in ("service_account", "iam_role"):
                factors.append("cloud_privileged")
                score += 0.1

            if identity.identity_type == "pat" and identity.provider in ("github", "gitlab"):
                factors.append("pat_token")
                score += 0.15

            if identity.expires_at:
                try:
                    exp = datetime.fromisoformat(identity.expires_at.replace("Z", "+00:00"))
                    # Use NHILifecycleScanner.EXPIRY_WINDOW constant
                    from .nhi_governance import NHILifecycleScanner
                    if (exp - datetime.now().astimezone()).days < NHILifecycleScanner.EXPIRY_WINDOW:
                        factors.append("expiring_soon")
                        score += 0.1
                except Exception:
                    pass

            score = min(score, 1.0)
            risk_level = "none"
            if score >= 0.7:
                risk_level = "critical"
            elif score >= 0.5:
                risk_level = "high"
            elif score >= 0.3:
                risk_level = "medium"
            elif score > 0:
                risk_level = "low"

            remediation = []
            if "no_owner" in factors:
                remediation.append("Assign a clear owner for this NHI")
            if "stale" in factors:
                remediation.append("Review and remove unused NHI")
            if "overdue_rotation" in factors:
                remediation.append("Rotate credentials immediately")
            if "broad_permissions" in factors:
                remediation.append("Apply principle of least privilege")
            if "expiring_soon" in factors:
                remediation.append("Renew or rotate before expiry")

            risks.append(
                NHIRisk(
                    identity_id=identity.identifier,
                    risk_score=score,
                    risk_level=risk_level,
                    factors=factors,
                    remediation=remediation,
                )
            )

        return risks


class NHIGovernanceScanner(BaseScanner):
    """Scanner for Non-Human Identity Governance."""

    SCANNER_NAME = "nhi_governance"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.discovery = NHIDiscovery(config.get("search_paths") if config else None)
        self.lifecycle = NHILifecycleScanner()
        self.scorer = NHIRiskScorer()

    def scan_path(self, target: str, recursive: bool = True) -> ScanResult:
        """Override to run full NHI governance."""
        import time

        start = time.perf_counter()
        search_paths = [Path(target).resolve()] if Path(target).is_dir() else [Path(target).parent.resolve()]

        self.discovery.search_paths = search_paths
        identities = self.discovery.discover_all()
        identities = self.lifecycle.scan(identities)
        risks = self.scorer.score(identities)

        findings = []
        for risk in risks:
            identity = next((i for i in identities if i.identifier == risk.identity_id), None)
            if identity:
                severity = "CRITICAL" if risk.risk_level == "critical" else "HIGH" if risk.risk_level == "high" else "MEDIUM" if risk.risk_level == "medium" else "LOW"
                findings.append(
                    self._create_finding(
                        rule_id=f"NHI-{risk.risk_level.upper()}",
                        severity=severity,
                        name=f"NHI Risk: {identity.name}",
                        description=f"Risk score: {risk.risk_score:.2f} | Factors: {', '.join(risk.factors) or 'none'}",
                        filepath=Path(identity.source_file),
                        line=0,
                        matched_text=f"Provider: {identity.provider}, Type: {identity.identity_type}",
                        metadata={
                            "nhi_identity": identity.to_dict(),
                            "nhi_risk": risk.to_dict(),
                        },
                    )
                )

        duration_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            scanner=self.SCANNER_NAME,
            target=target,
            findings=findings,
            files_scanned=len(search_paths),
            errors=[],
            scan_duration_ms=duration_ms,
        )

    def scan_file(self, filepath: Path) -> list[ScanFinding]:
        """Not used for NHI governance - use scan_path instead."""
        return []

    def run_full_governance(self, target: str) -> dict[str, Any]:
        """Run full NHI governance and return full report."""
        search_paths = [Path(target).resolve()] if Path(target).is_dir() else [Path(target).parent.resolve()]
        self.discovery.search_paths = search_paths
        identities = self.discovery.discover_all()
        identities = self.lifecycle.scan(identities)
        risks = self.scorer.score(identities)

        return {
            "discovered": [i.to_dict() for i in identities],
            "risks": [r.to_dict() for r in risks],
            "summary": {
                "total_identities": len(identities),
                "by_provider": self._count_by(identities, "provider"),
                "by_type": self._count_by(identities, "identity_type"),
                "by_risk_level": self._count_by(risks, "risk_level"),
            },
        }

    def _count_by(self, items: list, attr: str) -> dict[str, int]:
        counts = {}
        for item in items:
            val = getattr(item, attr, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts