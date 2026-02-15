"""
File Encryption and Decryption Module

Uses AES-256-GCM for authenticated encryption with PBKDF2-HMAC-SHA256
for key derivation from passwords. Provides confidentiality, integrity,
and authenticity guarantees.

File format:
    [16 bytes salt][12 bytes nonce][N bytes ciphertext + 16 bytes GCM tag]
"""

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# PBKDF2 iteration count — OWASP recommends >= 600,000 for SHA-256 (2023)
_PBKDF2_ITERATIONS = 600_000
_SALT_LENGTH = 16
_NONCE_LENGTH = 12
_KEY_LENGTH = 32  # 256 bits


class EncryptionError(Exception):
    """Raised when encryption fails."""


class DecryptionError(Exception):
    """Raised when decryption fails (wrong password, corrupted data, tampering)."""


class FileEncryptor:
    """AES-256-GCM file encryption with PBKDF2 key derivation.

    Each encryption operation generates a fresh salt and nonce,
    so encrypting the same file with the same password produces
    different ciphertext every time.
    """

    def __init__(self, iterations: int = _PBKDF2_ITERATIONS) -> None:
        self._iterations = iterations

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH,
            salt=salt,
            iterations=self._iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_bytes(self, data: bytes, password: str) -> bytes:
        """Encrypt raw bytes with a password.

        Returns: salt + nonce + ciphertext (with appended GCM tag).
        """
        salt = secrets.token_bytes(_SALT_LENGTH)
        nonce = secrets.token_bytes(_NONCE_LENGTH)
        key = self._derive_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

        return salt + nonce + ciphertext

    def decrypt_bytes(self, data: bytes, password: str) -> bytes:
        """Decrypt bytes that were encrypted with encrypt_bytes.

        Raises DecryptionError on wrong password or tampered data.
        """
        min_length = _SALT_LENGTH + _NONCE_LENGTH + 16  # 16 = GCM tag
        if len(data) < min_length:
            raise DecryptionError("Data is too short to be a valid encrypted payload.")

        salt = data[:_SALT_LENGTH]
        nonce = data[_SALT_LENGTH : _SALT_LENGTH + _NONCE_LENGTH]
        ciphertext = data[_SALT_LENGTH + _NONCE_LENGTH :]

        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception as exc:
            raise DecryptionError(
                "Decryption failed. Wrong password or corrupted/tampered data."
            ) from exc

    def encrypt_file(
        self,
        input_path: str | Path,
        password: str,
        output_path: Optional[str | Path] = None,
    ) -> Path:
        """Encrypt a file. Defaults to <input_path>.enc output.

        Returns the path to the encrypted file.
        """
        input_path = Path(input_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + ".enc")
        output_path = Path(output_path)

        try:
            plaintext = input_path.read_bytes()
            encrypted = self.encrypt_bytes(plaintext, password)
            output_path.write_bytes(encrypted)
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError(f"Failed to encrypt file: {exc}") from exc

        return output_path

    def decrypt_file(
        self,
        input_path: str | Path,
        password: str,
        output_path: Optional[str | Path] = None,
    ) -> Path:
        """Decrypt a file. Defaults to stripping .enc suffix for output.

        Returns the path to the decrypted file.
        """
        input_path = Path(input_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if output_path is None:
            if input_path.suffix == ".enc":
                output_path = input_path.with_suffix("")
            else:
                output_path = input_path.with_suffix(input_path.suffix + ".dec")
        output_path = Path(output_path)

        try:
            ciphertext = input_path.read_bytes()
            decrypted = self.decrypt_bytes(ciphertext, password)
            output_path.write_bytes(decrypted)
        except DecryptionError:
            raise
        except Exception as exc:
            raise DecryptionError(f"Failed to decrypt file: {exc}") from exc

        return output_path

    @staticmethod
    def secure_delete(path: str | Path, passes: int = 3) -> None:
        """Overwrite a file with random data before deleting it.

        This is a best-effort operation. Modern SSDs with wear leveling,
        journaling filesystems, and OS-level caching may retain copies.
        For true secure deletion, use full-disk encryption.
        """
        path = Path(path)
        if not path.is_file():
            return

        file_size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
