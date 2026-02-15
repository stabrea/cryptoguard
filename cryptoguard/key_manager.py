"""
Key Management Module

Generates, stores, rotates, and retrieves encryption keys.
Keys are stored encrypted under a master password using AES-256-GCM.

Key store format (JSON):
{
    "version": 1,
    "keys": {
        "<key_id>": {
            "encrypted_key": "<base64>",
            "created_at": "<ISO 8601>",
            "rotated_at": "<ISO 8601 | null>",
            "algorithm": "AES-256-GCM",
            "status": "active" | "rotated" | "revoked"
        }
    }
}
"""

import json
import secrets
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from cryptoguard.encryptor import FileEncryptor, DecryptionError


_DEFAULT_STORE_PATH = Path.home() / ".cryptoguard" / "keystore.json"
_KEY_LENGTH = 32  # 256 bits


@dataclass
class KeyInfo:
    """Metadata about a stored key (the key material itself is NOT included)."""

    key_id: str
    created_at: str
    rotated_at: Optional[str]
    algorithm: str
    status: str  # "active", "rotated", "revoked"


class KeyManagerError(Exception):
    """Raised on key management failures."""


class KeyManager:
    """Manage encryption keys protected by a master password.

    Keys are encrypted with AES-256-GCM before being written to disk.
    The master password is never stored — it must be provided for
    every operation that touches key material.
    """

    def __init__(
        self,
        store_path: str | Path = _DEFAULT_STORE_PATH,
    ) -> None:
        self._store_path = Path(store_path)
        self._encryptor = FileEncryptor()

    @property
    def store_path(self) -> Path:
        return self._store_path

    def initialize_store(self, master_password: str) -> Path:
        """Create a new empty key store.

        Raises KeyManagerError if the store already exists.
        """
        if self._store_path.exists():
            raise KeyManagerError(
                f"Key store already exists at {self._store_path}. "
                "Delete it first or use a different path."
            )

        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        store_data: dict = {"version": 1, "keys": {}}
        self._write_store(store_data, master_password)
        return self._store_path

    def generate_key(
        self,
        master_password: str,
        key_id: Optional[str] = None,
    ) -> str:
        """Generate a new AES-256 key and store it.

        Returns the key_id assigned to the new key.
        """
        if key_id is None:
            key_id = f"key-{secrets.token_hex(8)}"

        store = self._read_store(master_password)

        if key_id in store["keys"]:
            raise KeyManagerError(f"Key ID '{key_id}' already exists.")

        raw_key = secrets.token_bytes(_KEY_LENGTH)
        encrypted_key = self._encryptor.encrypt_bytes(raw_key, master_password)

        now = datetime.now(timezone.utc).isoformat()
        store["keys"][key_id] = {
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "created_at": now,
            "rotated_at": None,
            "algorithm": "AES-256-GCM",
            "status": "active",
        }

        self._write_store(store, master_password)
        return key_id

    def retrieve_key(self, master_password: str, key_id: str) -> bytes:
        """Retrieve the raw key material for a given key_id.

        Returns the 32-byte key. Raises KeyManagerError if not found
        or if the key has been revoked.
        """
        store = self._read_store(master_password)
        entry = store["keys"].get(key_id)

        if entry is None:
            raise KeyManagerError(f"Key '{key_id}' not found in store.")

        if entry["status"] == "revoked":
            raise KeyManagerError(
                f"Key '{key_id}' has been revoked and cannot be retrieved."
            )

        encrypted_key = base64.b64decode(entry["encrypted_key"])
        try:
            return self._encryptor.decrypt_bytes(encrypted_key, master_password)
        except DecryptionError as exc:
            raise KeyManagerError(f"Failed to decrypt key '{key_id}'.") from exc

    def rotate_key(self, master_password: str, key_id: str) -> str:
        """Rotate a key: mark the old one as rotated and generate a new one.

        Returns the new key_id. The old key remains accessible (status="rotated")
        for decrypting data encrypted with it.
        """
        store = self._read_store(master_password)
        entry = store["keys"].get(key_id)

        if entry is None:
            raise KeyManagerError(f"Key '{key_id}' not found.")

        if entry["status"] != "active":
            raise KeyManagerError(
                f"Only active keys can be rotated. Key '{key_id}' status: {entry['status']}."
            )

        # Mark old key as rotated
        entry["status"] = "rotated"
        entry["rotated_at"] = datetime.now(timezone.utc).isoformat()
        self._write_store(store, master_password)

        # Generate replacement
        new_key_id = f"{key_id}-rotated-{secrets.token_hex(4)}"
        self.generate_key(master_password, key_id=new_key_id)

        return new_key_id

    def revoke_key(self, master_password: str, key_id: str) -> None:
        """Revoke a key. Revoked keys cannot be retrieved.

        The encrypted key material is destroyed in the store.
        """
        store = self._read_store(master_password)
        entry = store["keys"].get(key_id)

        if entry is None:
            raise KeyManagerError(f"Key '{key_id}' not found.")

        entry["status"] = "revoked"
        entry["encrypted_key"] = ""  # Destroy key material
        entry["rotated_at"] = datetime.now(timezone.utc).isoformat()

        self._write_store(store, master_password)

    def list_keys(self, master_password: str) -> list[KeyInfo]:
        """List all keys in the store with their metadata."""
        store = self._read_store(master_password)
        result: list[KeyInfo] = []

        for kid, entry in store["keys"].items():
            result.append(
                KeyInfo(
                    key_id=kid,
                    created_at=entry["created_at"],
                    rotated_at=entry.get("rotated_at"),
                    algorithm=entry["algorithm"],
                    status=entry["status"],
                )
            )

        return result

    def export_key(
        self,
        master_password: str,
        key_id: str,
        export_password: str,
    ) -> str:
        """Export a key encrypted with a separate export password.

        Returns a base64-encoded encrypted blob that can be imported
        on another machine.
        """
        raw_key = self.retrieve_key(master_password, key_id)
        encrypted = self._encryptor.encrypt_bytes(raw_key, export_password)
        return base64.b64encode(encrypted).decode("ascii")

    def import_key(
        self,
        master_password: str,
        export_blob: str,
        export_password: str,
        key_id: Optional[str] = None,
    ) -> str:
        """Import a key from an export blob.

        Returns the key_id assigned to the imported key.
        """
        if key_id is None:
            key_id = f"imported-{secrets.token_hex(8)}"

        encrypted = base64.b64decode(export_blob)
        try:
            raw_key = self._encryptor.decrypt_bytes(encrypted, export_password)
        except DecryptionError as exc:
            raise KeyManagerError("Failed to decrypt export blob.") from exc

        if len(raw_key) != _KEY_LENGTH:
            raise KeyManagerError(
                f"Imported key has wrong length ({len(raw_key)} bytes, expected {_KEY_LENGTH})."
            )

        # Re-encrypt under master password and store
        store = self._read_store(master_password)
        if key_id in store["keys"]:
            raise KeyManagerError(f"Key ID '{key_id}' already exists.")

        re_encrypted = self._encryptor.encrypt_bytes(raw_key, master_password)
        now = datetime.now(timezone.utc).isoformat()

        store["keys"][key_id] = {
            "encrypted_key": base64.b64encode(re_encrypted).decode("ascii"),
            "created_at": now,
            "rotated_at": None,
            "algorithm": "AES-256-GCM",
            "status": "active",
        }

        self._write_store(store, master_password)
        return key_id

    def _read_store(self, master_password: str) -> dict:
        """Read and decrypt the key store."""
        if not self._store_path.exists():
            raise KeyManagerError(
                f"Key store not found at {self._store_path}. "
                "Run 'initialize_store' first."
            )

        encrypted = self._store_path.read_bytes()
        try:
            decrypted = self._encryptor.decrypt_bytes(encrypted, master_password)
        except DecryptionError as exc:
            raise KeyManagerError(
                "Failed to unlock key store. Wrong master password?"
            ) from exc

        try:
            return json.loads(decrypted.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise KeyManagerError("Key store data is corrupted.") from exc

    def _write_store(self, data: dict, master_password: str) -> None:
        """Encrypt and write the key store."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(data, indent=2).encode("utf-8")
        encrypted = self._encryptor.encrypt_bytes(raw, master_password)
        self._store_path.write_bytes(encrypted)
