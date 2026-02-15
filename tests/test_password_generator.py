"""Tests for the password generator module."""

import string

import pytest

from cryptoguard.password_generator import PasswordGenerator, GeneratedPassword, _WORDLIST


def test_generated_password_length_matches_requested():
    for length in [8, 12, 20, 32, 64]:
        result = PasswordGenerator.generate(length=length)
        assert result.length == length
        assert len(result.password) == length


def test_generated_password_default_length():
    result = PasswordGenerator.generate()
    assert result.length == 20
    assert len(result.password) == 20


def test_generated_password_contains_all_character_sets():
    # With all sets enabled and length >= 4, we should get at least one from each
    result = PasswordGenerator.generate(length=20)
    pw = result.password

    has_lower = any(c in string.ascii_lowercase for c in pw)
    has_upper = any(c in string.ascii_uppercase for c in pw)
    has_digit = any(c in string.digits for c in pw)
    has_special = any(c not in string.ascii_letters + string.digits for c in pw)

    assert has_lower
    assert has_upper
    assert has_digit
    assert has_special


def test_generated_password_no_special():
    result = PasswordGenerator.generate(length=16, use_special=False)
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    assert not any(c in special_chars for c in result.password)


def test_generated_password_digits_only():
    result = PasswordGenerator.generate(
        length=10,
        use_uppercase=False,
        use_lowercase=False,
        use_digits=True,
        use_special=False,
    )
    assert result.password.isdigit()
    assert len(result.password) == 10


def test_generated_password_excludes_chars():
    result = PasswordGenerator.generate(length=100, exclude_chars="0Ol1I")
    pw = result.password
    for ch in "0Ol1I":
        assert ch not in pw


def test_minimum_length_raises():
    with pytest.raises(ValueError, match="Minimum password length"):
        PasswordGenerator.generate(length=3)


def test_no_characters_available_raises():
    with pytest.raises(ValueError):
        PasswordGenerator.generate(
            length=10,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_special=False,
        )


def test_generated_password_type():
    result = PasswordGenerator.generate()
    assert isinstance(result, GeneratedPassword)
    assert result.type == "random"
    assert result.entropy_bits > 0


def test_passphrase_generation():
    result = PasswordGenerator.generate_passphrase(word_count=5, separator="-")
    assert isinstance(result, GeneratedPassword)
    assert result.type == "passphrase"
    # Should have separator-separated words
    parts = result.password.split("-")
    assert len(parts) == 5


def test_passphrase_minimum_words():
    with pytest.raises(ValueError, match="Minimum 3 words"):
        PasswordGenerator.generate_passphrase(word_count=2)


def test_passphrase_capitalize():
    result = PasswordGenerator.generate_passphrase(
        word_count=4, capitalize=True, include_number=False, separator="-"
    )
    for word in result.password.split("-"):
        assert word[0].isupper()


def test_pin_generation():
    result = PasswordGenerator.generate_pin(length=6)
    assert result.type == "pin"
    assert len(result.password) == 6
    assert result.password.isdigit()


def test_pin_minimum_length():
    with pytest.raises(ValueError, match="Minimum PIN length"):
        PasswordGenerator.generate_pin(length=3)


def test_wordlist_is_populated():
    assert len(_WORDLIST) > 100


def test_unique_passwords_generated():
    passwords = {PasswordGenerator.generate(length=20).password for _ in range(10)}
    # Extremely unlikely to get duplicates with 20-char random passwords
    assert len(passwords) == 10
