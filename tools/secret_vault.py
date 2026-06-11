"""
Secret Vault — Find Evil Hackathon
Encrypted credential storage with PBKDF2 key derivation.
Based on Elliot Cybersecurity Lab's secret_vault.py
"""

import base64
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretVault:
    """Encrypted vault for API keys and secrets."""

    MIN_PASSWORD_LENGTH = 16
    KDF_ITERATIONS = 600000

    def __init__(self, vault_path: str | None = None, master_password: str | None = None):
        self.vault_path = Path(vault_path or os.getenv("DAVI_VAULT_PATH", "tools/vault.enc"))
        self.salt_path = Path(f"{self.vault_path}.salt")
        self.master_password = master_password or os.getenv("DAVI_MASTER_PASSWORD")
        if not self.master_password:
            raise RuntimeError("DAVI_MASTER_PASSWORD is required; refusing to use an implicit vault password")
        if len(self.master_password) < self.MIN_PASSWORD_LENGTH:
            raise RuntimeError(f"DAVI_MASTER_PASSWORD must be at least {self.MIN_PASSWORD_LENGTH} characters")
        self.key = self._derive_key(self.master_password)
        self.fernet = Fernet(self.key)
        self.secrets = {}
        self._load()

    def _derive_key(self, password: str) -> bytes:
        salt = self._load_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_or_create_salt(self) -> bytes:
        if self.salt_path.exists():
            return self.salt_path.read_bytes()
        if self.vault_path.exists():
            raise RuntimeError(
                f"Vault exists without salt sidecar: {self.salt_path}. "
                "Set DAVI_VAULT_ALLOW_LEGACY=1 only in a controlled migration."
            )
        salt = secrets.token_bytes(16)
        self.salt_path.parent.mkdir(parents=True, exist_ok=True)
        self.salt_path.write_bytes(salt)
        try:
            os.chmod(self.salt_path, 0o600)
        except OSError:
            pass
        return salt

    def _load(self):
        if self.vault_path.exists():
            try:
                encrypted_data = self.vault_path.read_bytes()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                self.secrets = json.loads(decrypted_data.decode())
            except InvalidToken as exc:
                raise RuntimeError("Vault decrypt failed; wrong DAVI_MASTER_PASSWORD or corrupted vault") from exc
            except (json.JSONDecodeError, OSError) as exc:
                raise RuntimeError(f"Vault load failed: {exc}") from exc

    def _save(self):
        try:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps(self.secrets).encode()
            encrypted_data = self.fernet.encrypt(data)
            self.vault_path.write_bytes(encrypted_data)
            os.chmod(self.vault_path, 0o600)
        except OSError as exc:
            raise RuntimeError(f"Vault save failed: {exc}") from exc

    def set(self, key: str, value: str):
        self.secrets[key] = value
        self._save()

    def get(self, key: str, default: Any | None = None) -> Any | None:
        return self.secrets.get(key, default)

    def list_keys(self) -> list[str]:
        return list(self.secrets.keys())

    def delete(self, key: str):
        if key in self.secrets:
            del self.secrets[key]
            self._save()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 secret_vault.py [set|get|list|delete] key [value] [--reveal]")
        sys.exit(1)

    action = sys.argv[1]
    try:
        vault = SecretVault()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if action == "set" and len(sys.argv) == 4:
        vault.set(sys.argv[2], sys.argv[3])
        print(f"Secret '{sys.argv[2]}' guardado.")
    elif action == "get" and len(sys.argv) >= 3:
        val = vault.get(sys.argv[2])
        if val:
            if "--reveal" in sys.argv[3:]:
                print(val)
            else:
                print(f"Secret '{sys.argv[2]}' existe. Usa --reveal para imprimirlo.")
        else:
            print(f"Secret '{sys.argv[2]}' no encontrado.")
            sys.exit(1)
    elif action == "list":
        for k in vault.list_keys():
            print(k)
    elif action == "delete" and len(sys.argv) >= 3:
        vault.delete(sys.argv[2])
        print(f"Secret '{sys.argv[2]}' eliminado.")
    else:
        print("Uso: python3 secret_vault.py [set|get|list|delete] key [value] [--reveal]")
        sys.exit(1)