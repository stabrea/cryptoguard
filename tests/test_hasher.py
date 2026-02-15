"""Tests for the hashing utilities module."""

import hashlib

from cryptoguard.hasher import Hasher, _SUPPORTED_ALGORITHMS


def test_sha256_known_hash():
    """SHA-256 of empty string is a well-known value."""
    expected = hashlib.sha256(b"").hexdigest()
    result = Hasher.hash_bytes(b"", "sha256")
    assert result == expected


def test_sha256_hello_world():
    expected = hashlib.sha256(b"Hello, World!").hexdigest()
    result = Hasher.hash_string("Hello, World!", "sha256")
    assert result == expected


def test_sha512_hash():
    expected = hashlib.sha512(b"test data").hexdigest()
    result = Hasher.hash_bytes(b"test data", "sha512")
    assert result == expected


def test_blake2b_hash():
    expected = hashlib.blake2b(b"blake2 test").hexdigest()
    result = Hasher.hash_bytes(b"blake2 test", "blake2b")
    assert result == expected


def test_blake2b_string_hash():
    data = "Hello BLAKE2"
    expected = hashlib.blake2b(data.encode("utf-8")).hexdigest()
    result = Hasher.hash_string(data, "blake2b")
    assert result == expected


def test_compare_hashes_matching():
    h1 = Hasher.hash_string("test", "sha256")
    h2 = Hasher.hash_string("test", "sha256")
    assert Hasher.compare_hashes(h1, h2) is True


def test_compare_hashes_non_matching():
    h1 = Hasher.hash_string("foo", "sha256")
    h2 = Hasher.hash_string("bar", "sha256")
    assert Hasher.compare_hashes(h1, h2) is False


def test_compare_hashes_case_insensitive():
    h = Hasher.hash_string("data", "sha256")
    assert Hasher.compare_hashes(h.upper(), h.lower()) is True


def test_supported_algorithms():
    algos = Hasher.supported_algorithms()
    assert "sha256" in algos
    assert "sha512" in algos
    assert "blake2b" in algos
    assert len(algos) == len(_SUPPORTED_ALGORITHMS)


def test_different_algorithms_produce_different_hashes():
    data = b"same input"
    sha256 = Hasher.hash_bytes(data, "sha256")
    sha512 = Hasher.hash_bytes(data, "sha512")
    blake2 = Hasher.hash_bytes(data, "blake2b")

    assert sha256 != sha512
    assert sha256 != blake2
    assert sha512 != blake2


def test_hash_deterministic():
    """Same input always produces the same hash."""
    for _ in range(5):
        assert Hasher.hash_string("consistent", "sha256") == Hasher.hash_string("consistent", "sha256")
