"""
Hashing Utilities Module

Provides cryptographic hashing (SHA-256, SHA-512, BLAKE2b), file integrity
verification, and constant-time hash comparison to prevent timing attacks.
"""

import hashlib
import hmac
from pathlib import Path
from typing import Literal

# Chunk size for streaming file hashes (64 KiB)
_CHUNK_SIZE = 65_536

HashAlgorithm = Literal["sha256", "sha512", "blake2b"]

_SUPPORTED_ALGORITHMS: dict[str, str] = {
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "blake2b": "BLAKE2b",
}


class HashError(Exception):
    """Raised when a hashing operation fails."""


class Hasher:
    """Cryptographic hashing and integrity verification."""

    @staticmethod
    def supported_algorithms() -> list[str]:
        """Return list of supported algorithm names."""
        return list(_SUPPORTED_ALGORITHMS.keys())

    @staticmethod
    def hash_string(
        data: str,
        algorithm: HashAlgorithm = "sha256",
        encoding: str = "utf-8",
    ) -> str:
        """Hash a string and return the hex digest."""
        return Hasher.hash_bytes(data.encode(encoding), algorithm)

    @staticmethod
    def hash_bytes(data: bytes, algorithm: HashAlgorithm = "sha256") -> str:
        """Hash raw bytes and return the hex digest."""
        h = Hasher._get_hasher(algorithm)
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def hash_file(
        path: str | Path,
        algorithm: HashAlgorithm = "sha256",
    ) -> str:
        """Stream-hash a file and return the hex digest.

        Reads the file in chunks so arbitrarily large files can be hashed
        without loading them entirely into memory.
        """
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        h = Hasher._get_hasher(algorithm)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def verify_file(
        path: str | Path,
        expected_hash: str,
        algorithm: HashAlgorithm = "sha256",
    ) -> bool:
        """Verify a file's integrity against an expected hash.

        Uses constant-time comparison to prevent timing attacks.
        """
        actual_hash = Hasher.hash_file(path, algorithm)
        return Hasher.compare_hashes(actual_hash, expected_hash)

    @staticmethod
    def compare_hashes(hash_a: str, hash_b: str) -> bool:
        """Constant-time comparison of two hex-encoded hashes.

        Prevents timing side-channel attacks where an attacker
        could infer partial hash matches from response time.
        """
        return hmac.compare_digest(
            hash_a.lower().encode("ascii"),
            hash_b.lower().encode("ascii"),
        )

    @staticmethod
    def hash_multiple_files(
        paths: list[str | Path],
        algorithm: HashAlgorithm = "sha256",
    ) -> dict[str, str]:
        """Hash multiple files and return a mapping of path -> hex digest."""
        results: dict[str, str] = {}
        for p in paths:
            path = Path(p)
            try:
                results[str(path)] = Hasher.hash_file(path, algorithm)
            except FileNotFoundError:
                results[str(path)] = "<file not found>"
            except Exception as exc:
                results[str(path)] = f"<error: {exc}>"
        return results

    @staticmethod
    def generate_checksum_file(
        paths: list[str | Path],
        output_path: str | Path,
        algorithm: HashAlgorithm = "sha256",
    ) -> Path:
        """Generate a checksum file in the format: <hash>  <filename>

        Compatible with sha256sum / sha512sum verification format.
        """
        output_path = Path(output_path)
        hashes = Hasher.hash_multiple_files(paths, algorithm)

        lines: list[str] = []
        for file_path, digest in hashes.items():
            if not digest.startswith("<"):
                lines.append(f"{digest}  {file_path}")

        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return output_path

    @staticmethod
    def verify_checksum_file(
        checksum_path: str | Path,
        algorithm: HashAlgorithm = "sha256",
    ) -> dict[str, bool]:
        """Verify files listed in a checksum file.

        Returns a mapping of filename -> pass/fail.
        """
        checksum_path = Path(checksum_path)
        if not checksum_path.is_file():
            raise FileNotFoundError(f"Checksum file not found: {checksum_path}")

        results: dict[str, bool] = {}
        for line in checksum_path.read_text(encoding="utf-8").strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: <hash>  <filename> (two spaces)
            parts = line.split("  ", maxsplit=1)
            if len(parts) != 2:
                continue
            expected_hash, file_path = parts
            try:
                results[file_path] = Hasher.verify_file(
                    file_path, expected_hash, algorithm
                )
            except FileNotFoundError:
                results[file_path] = False

        return results

    @staticmethod
    def _get_hasher(algorithm: HashAlgorithm) -> "hashlib._Hash":
        """Create a hashlib hash object for the given algorithm."""
        if algorithm == "sha256":
            return hashlib.sha256()
        elif algorithm == "sha512":
            return hashlib.sha512()
        elif algorithm == "blake2b":
            return hashlib.blake2b()
        else:
            raise HashError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported: {', '.join(_SUPPORTED_ALGORITHMS.keys())}"
            )
