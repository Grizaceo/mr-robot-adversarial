"""
Alert System with HMAC-signed Audit Logging — Find Evil Hackathon
Based on Elliot Cybersecurity Lab's alert_system.py
"""

import hmac
import hashlib
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional


_SENSITIVE_KEY_RE = re.compile(
    r"(?:secret|token|password|passwd|api[_-]?key|credential|auth|private[_-]?key)",
    re.IGNORECASE,
)

LAB_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(LAB_ROOT, "logs")
ALERT_STORE = os.path.join(LAB_ROOT, "reports", "active_alerts.json")
AUDIT_ANCHOR = os.path.join(LAB_ROOT, "baselines", "audit_hmac_anchor.json")


class AlertSystem:
    """Centralized alerting with tamper-evident audit logging."""

    DEDUP_WINDOW_SECONDS = 1800  # 30 minutes

    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)

        logging.basicConfig(
            filename=os.path.join(LOG_DIR, "alerts.log"),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] [%(source)s] %(message)s",
        )
        self.logger = logging.getLogger("AlertSystem")
        self._recent_alerts = {}

    def _log_event(self, level: str, source: str, message: str, data: dict[str, Any] | None = None):
        # Deduplication
        dedup_key = f"{level}:{source}:{message}"
        now = datetime.now().timestamp()
        last_seen = self._recent_alerts.get(dedup_key, 0)
        if now - last_seen < self.DEDUP_WINDOW_SECONDS:
            return
        self._recent_alerts[dedup_key] = now

        timestamp = datetime.now().isoformat()
        alert = {
            "timestamp": timestamp,
            "level": level,
            "source": source,
            "message": message,
            "data": data or {},
        }

        # Log to file
        extra = {"source": source}
        if level == "CRITICAL":
            self.logger.critical(message, extra=extra)
        elif level == "WARN":
            self.logger.warning(message, extra=extra)
        else:
            self.logger.info(message, extra=extra)

        # Persist active alerts
        self._update_active_alerts(alert)

        # Visual output
        color = ""
        if level == "CRITICAL":
            color = "\033[91m[CRITICAL]\033[0m"
        elif level == "WARN":
            color = "\033[93m[WARNING]\033[0m"
        else:
            color = "\033[94m[INFO]\033[0m"

        print(f"{color} [{source}] {message}")

    def _update_active_alerts(self, alert: dict):
        alerts = []
        if os.path.exists(ALERT_STORE):
            try:
                with open(ALERT_STORE, "r") as f:
                    alerts = json.load(f)
            except (json.JSONDecodeError, OSError, PermissionError):
                alerts = []

        alerts.append(alert)
        alerts = alerts[-100:]

        try:
            os.makedirs(os.path.dirname(ALERT_STORE), exist_ok=True)
            with open(ALERT_STORE, "w") as f:
                json.dump(alerts, f, indent=4)
        except (OSError, PermissionError) as exc:
            print(f"[AlertSystem] WARNING: could not persist alert store: {exc}", file=sys.stderr)

    def info(self, source: str, message: str, data: dict[str, Any] | None = None):
        self._log_event("INFO", source, message, data)
        self._append_audit("INFO", source, message, data)

    def warn(self, source: str, message: str, data: dict[str, Any] | None = None):
        self._log_event("WARN", source, message, data)
        self._append_audit("WARN", source, message, data)

    def critical(self, source: str, message: str, data: dict[str, Any] | None = None):
        self._log_event("CRITICAL", source, message, data)
        self._append_audit("CRITICAL", source, message, data)
        self._emit_webhooks(source, message, data)

    # Webhook fan-out (Telegram + Slack)
    @staticmethod
    def _sanitize_webhook_data(data: Any, *, max_depth: int = 6) -> Any:
        if data is None:
            return {}
        if max_depth <= 0:
            return "[TRUNCATED]"

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_str = str(key)
                if _SENSITIVE_KEY_RE.search(key_str):
                    sanitized[key_str] = "[REDACTED]"
                else:
                    sanitized[key_str] = AlertSystem._sanitize_webhook_data(value, max_depth=max_depth - 1)
            return sanitized

        if isinstance(data, (list, tuple)):
            return [AlertSystem._sanitize_webhook_data(item, max_depth=max_depth - 1) for item in data[:50]]

        if isinstance(data, str) and len(data) > 500:
            return data[:500] + "…[TRUNCATED]"
        return data

    def _emit_webhooks(self, source: str, message: str, data: dict[str, Any] | None):
        text = f"🚨 [Elliot/CRITICAL] [{source}] {message}"
        if data:
            safe_data = self._sanitize_webhook_data(data)
            text += f"\n```\n{json.dumps(safe_data, indent=2)[:1500]}\n```"

        # Telegram
        tg_token = os.getenv("DAVI_TELEGRAM_BOT_TOKEN")
        tg_chat = os.getenv("DAVI_TELEGRAM_CHAT_ID")
        if tg_token and tg_chat:
            self._post_json(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                {"chat_id": tg_chat, "text": text[:4000], "parse_mode": "Markdown"},
            )

        # Slack
        slack_url = os.getenv("DAVI_SLACK_WEBHOOK_URL")
        if slack_url:
            self._post_json(slack_url, {"text": text[:4000]})

    @staticmethod
    def _post_json(url: str, payload: dict):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5).read()
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            pass  # Best effort

    # HMAC-signed audit log
    def _audit_path(self) -> str:
        return os.path.join(LAB_ROOT, "reports", "audit.jsonl")

    def _audit_secret(self) -> Optional[bytes]:
        """Resolve HMAC signing key. No hardcoded fallback."""
        explicit = os.getenv("DAVI_AUDIT_SECRET")
        if explicit:
            return explicit.encode()
        if os.getenv("DAVI_AUTONOMOUS") == "1":
            raise RuntimeError(
                "DAVI_AUDIT_SECRET required for tamper-evident audit signing "
                "in autonomous mode (baseline fallback is disabled)"
            )
        baseline = os.path.join(LAB_ROOT, "baselines", "hermes_agent_baseline.json")
        if os.path.exists(baseline):
            with open(baseline, "rb") as f:
                return hashlib.sha256(f.read()).digest()
        return None

    def _append_audit(self, level: str, source: str, message: str, data: dict[str, Any] | None):
        secret = self._audit_secret()
        if secret is None:
            print(
                "[AlertSystem] WARNING: audit log entry not HMAC-signed "
                "(set DAVI_AUDIT_SECRET or create baselines/hermes_agent_baseline.json)",
                file=sys.stderr,
            )
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "source": source,
            "message": message,
            "data": data or {},
        }
        body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record["hmac"] = hmac.new(secret, body, hashlib.sha256).hexdigest()
        try:
            os.makedirs(os.path.dirname(self._audit_path()), exist_ok=True)
            with open(self._audit_path(), "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass

    @classmethod
    def verify_audit(cls, path: str | None = None, start_line: int = 1) -> tuple[bool, list[int]]:
        """Verify integrity of the HMAC-signed audit log."""
        self = cls()
        path = path or self._audit_path()
        try:
            secret = self._audit_secret()
        except RuntimeError as exc:
            print(f"Audit verification unavailable: {exc}")
            return False, []
        if secret is None:
            print("Audit verification skipped: no DAVI_AUDIT_SECRET or baseline available")
            return True, []
        bad: list[int] = []
        if not os.path.exists(path):
            return True, []
        with open(path) as f:
            for ln_no, line in enumerate(f, 1):
                if ln_no < start_line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    bad.append(ln_no)
                    continue
                claimed = rec.pop("hmac", None)
                body = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
                expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
                if not (claimed and hmac.compare_digest(claimed, expected)):
                    bad.append(ln_no)
        return (not bad), bad

    @staticmethod
    def _line_count(path: str) -> int:
        if not os.path.exists(path):
            return 0
        with open(path) as f:
            return sum(1 for _ in f)

    @classmethod
    def write_audit_anchor(cls, path: str | None = None):
        self = cls()
        path = path or self._audit_path()
        anchor = {
            "audit_path": path,
            "line_count": self._line_count(path),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "note": "Lines up to line_count predate the current HMAC verification baseline.",
        }
        os.makedirs(os.path.dirname(AUDIT_ANCHOR), exist_ok=True)
        with open(AUDIT_ANCHOR, "w") as f:
            json.dump(anchor, f, indent=2)
            f.write("\n")
        return anchor

    @staticmethod
    def read_audit_anchor() -> dict:
        if not os.path.exists(AUDIT_ANCHOR):
            return {}
        try:
            with open(AUDIT_ANCHOR) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Elliot alert system utilities")
    parser.add_argument("--verify-audit", action="store_true", help="Verify HMAC integrity of reports/audit.jsonl")
    parser.add_argument("--strict", action="store_true", help="Verify entire audit log, ignoring anchor")
    parser.add_argument("--anchor-current", action="store_true", help="Baseline existing audit lines as historical")
    parser.add_argument("--smoke-test", action="store_true", help="Emit local INFO/WARN test alerts only")
    args = parser.parse_args()

    if args.anchor_current:
        anchor = AlertSystem.write_audit_anchor()
        print(f"Audit anchor written: line_count={anchor['line_count']}")
        return 0

    if args.verify_audit:
        anchor = AlertSystem.read_audit_anchor()
        start_line = 1 if args.strict else int(anchor.get("line_count", 0)) + 1
        ok, bad_lines = AlertSystem.verify_audit(start_line=start_line)
        if ok:
            scope = "entire log" if args.strict else f"lines >= {start_line}"
            print(f"Audit log HMAC verification OK ({scope})")
            return 0
        print(f"Audit log HMAC verification FAILED: bad lines={bad_lines}")
        return 1

    if args.smoke_test:
        asys = AlertSystem()
        asys.info("SYSTEM", "Alert System smoke test initialized.")
        asys.warn("SCANNERS", "Alert System smoke test warning.")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())