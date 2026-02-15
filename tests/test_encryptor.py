"""Tests for the file encryptor module."""

import pytest

from cryptoguard.encryptor import FileEncryptor, DecryptionError


def _make_encryptor() -> FileEncryptor:
    # Use fewer iterations for fast tests
    return FileEncryptor(iterations=1000)


def test_encrypt_decrypt_roundtrip():
    enc = _make_encryptor()
    original = b"Hello, World! This is secret data."
    password = "test-password-123"

    encrypted = enc.encrypt_bytes(original, password)
    decrypted = enc.decrypt_bytes(encrypted, password)

    assert decrypted == original


def test_encrypt_decrypt_roundtrip_empty_data():
    enc = _make_encryptor()
    original = b""
    password = "mypassword"

    encrypted = enc.encrypt_bytes(original, password)
    decrypted = enc.decrypt_bytes(encrypted, password)

    assert decrypted == original


def test_encrypt_decrypt_roundtrip_binary_data():
    enc = _make_encryptor()
    original = bytes(range(256))
    password = "binary-password"

    encrypted = enc.encrypt_bytes(original, password)
    decrypted = enc.decrypt_bytes(encrypted, password)

    assert decrypted == original


def test_wrong_password_fails_decryption():
    enc = _make_encryptor()
    original = b"Sensitive data"
    encrypted = enc.encrypt_bytes(original, "correct-password")

    with pytest.raises(DecryptionError):
        enc.decrypt_bytes(encrypted, "wrong-password")


def test_different_inputs_produce_different_ciphertext():
    enc = _make_encryptor()
    password = "same-password"

    ct1 = enc.encrypt_bytes(b"message one", password)
    ct2 = enc.encrypt_bytes(b"message two", password)

    assert ct1 != ct2


def test_same_input_produces_different_ciphertext():
    """Each encryption uses a fresh salt and nonce, so output differs."""
    enc = _make_encryptor()
    data = b"identical data"
    password = "same-password"

    ct1 = enc.encrypt_bytes(data, password)
    ct2 = enc.encrypt_bytes(data, password)

    assert ct1 != ct2


def test_encrypted_output_longer_than_input():
    enc = _make_encryptor()
    data = b"short"
    encrypted = enc.encrypt_bytes(data, "pw")

    # Output should include 16-byte salt + 12-byte nonce + ciphertext + 16-byte GCM tag
    min_overhead = 16 + 12 + 16  # salt + nonce + tag
    assert len(encrypted) >= len(data) + min_overhead


def test_truncated_ciphertext_raises():
    enc = _make_encryptor()
    with pytest.raises(DecryptionError, match="too short"):
        enc.decrypt_bytes(b"short", "password")


def test_tampered_ciphertext_raises():
    enc = _make_encryptor()
    encrypted = enc.encrypt_bytes(b"valid data", "password")

    # Flip a byte in the ciphertext portion
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF
    tampered = bytes(tampered)

    with pytest.raises(DecryptionError):
        enc.decrypt_bytes(tampered, "password")
