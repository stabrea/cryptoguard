"""
Password Strength Analysis Module

Evaluates passwords on multiple axes: entropy, length, character diversity,
common pattern detection, and simulated breach database checks.
Produces a strength score from 0 (catastrophic) to 100 (excellent).
"""

import math
import re
import hashlib
import string
from dataclasses import dataclass, field
from typing import Optional


# Common passwords (top subset for offline checking).
# In production, use the full Have I Been Pwned list or a k-anonymity API.
_COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "michael", "shadow", "123123",
    "654321", "superman", "qazwsx", "password1", "password123",
    "admin", "welcome", "hello", "charlie", "donald", "login",
    "starwars", "solo", "princess", "passw0rd", "p@ssword", "p@ssw0rd",
}

# Keyboard sequences and patterns
_KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

_SEQUENTIAL_PATTERNS = [
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
]


@dataclass
class PasswordReport:
    """Detailed password analysis report."""

    password_length: int
    score: int  # 0–100
    rating: str  # "Very Weak" / "Weak" / "Fair" / "Strong" / "Very Strong"
    entropy_bits: float
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    character_sets: list[str] = field(default_factory=list)
    is_common: bool = False
    has_breach_hit: bool = False  # Simulated


class PasswordAnalyzer:
    """Analyze password strength using multiple heuristics."""

    @staticmethod
    def analyze(
        password: str,
        check_breach: bool = True,
    ) -> PasswordReport:
        """Run full analysis on a password and return a report."""
        warnings: list[str] = []
        suggestions: list[str] = []
        char_sets: list[str] = []

        length = len(password)

        # --- Character set analysis ---
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        if has_lower:
            char_sets.append("lowercase")
        if has_upper:
            char_sets.append("uppercase")
        if has_digit:
            char_sets.append("digits")
        if has_special:
            char_sets.append("special")

        # --- Entropy calculation ---
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_special:
            pool_size += 33  # common special chars

        entropy = length * math.log2(pool_size) if pool_size > 0 and length > 0 else 0.0

        # --- Scoring (start at 0, accumulate points) ---
        score = 0.0

        # Length contribution (up to 35 points)
        score += min(length * 2.5, 35.0)

        # Entropy contribution (up to 30 points)
        score += min(entropy / 4.0, 30.0)

        # Character diversity (up to 20 points)
        diversity_count = len(char_sets)
        score += diversity_count * 5.0

        # Bonus for long passwords (up to 15 points)
        if length >= 16:
            score += 15.0
        elif length >= 12:
            score += 10.0
        elif length >= 10:
            score += 5.0

        # --- Penalties ---

        # Common password check
        is_common = password.lower() in _COMMON_PASSWORDS
        if is_common:
            score = min(score, 5.0)
            warnings.append("This password is in the list of commonly breached passwords.")

        # Too short
        if length < 8:
            score *= 0.4
            warnings.append("Password is shorter than 8 characters.")
            suggestions.append("Use at least 12 characters for adequate security.")

        # All same character
        if len(set(password)) == 1:
            score = min(score, 5.0)
            warnings.append("Password consists of a single repeated character.")

        # Sequential characters (abc, 123)
        if PasswordAnalyzer._has_sequential(password, 4):
            score *= 0.6
            warnings.append("Contains sequential characters (e.g., abcd, 1234).")

        # Keyboard walk (qwerty, asdf)
        if PasswordAnalyzer._has_keyboard_walk(password, 4):
            score *= 0.6
            warnings.append("Contains keyboard walk pattern (e.g., qwerty, asdf).")

        # Repeated patterns (abcabc)
        if PasswordAnalyzer._has_repeated_pattern(password):
            score *= 0.7
            warnings.append("Contains repeated patterns.")

        # Only digits
        if password.isdigit():
            score *= 0.5
            warnings.append("Password contains only digits.")
            suggestions.append("Mix in letters and special characters.")

        # Missing character sets
        if not has_upper:
            suggestions.append("Add uppercase letters.")
        if not has_lower:
            suggestions.append("Add lowercase letters.")
        if not has_digit:
            suggestions.append("Add numbers.")
        if not has_special:
            suggestions.append("Add special characters (!@#$%^&*).")

        # --- Breach simulation ---
        has_breach_hit = False
        if check_breach:
            has_breach_hit = PasswordAnalyzer._simulate_breach_check(password)
            if has_breach_hit:
                score = min(score, 10.0)
                warnings.append(
                    "Password appears in simulated breach database. "
                    "In production, check against Have I Been Pwned."
                )

        # Clamp score
        final_score = max(0, min(100, int(score)))

        # Rating
        if final_score >= 80:
            rating = "Very Strong"
        elif final_score >= 60:
            rating = "Strong"
        elif final_score >= 40:
            rating = "Fair"
        elif final_score >= 20:
            rating = "Weak"
        else:
            rating = "Very Weak"

        if not suggestions and final_score < 80:
            suggestions.append("Consider using a passphrase of 4+ random words.")

        return PasswordReport(
            password_length=length,
            score=final_score,
            rating=rating,
            entropy_bits=round(entropy, 2),
            warnings=warnings,
            suggestions=suggestions,
            character_sets=char_sets,
            is_common=is_common,
            has_breach_hit=has_breach_hit,
        )

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate the Shannon entropy of a password in bits."""
        if not password:
            return 0.0

        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"\d", password):
            pool += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            pool += 33

        if pool == 0:
            return 0.0

        return len(password) * math.log2(pool)

    @staticmethod
    def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
        """Estimate brute-force crack time given entropy and attack speed.

        Default assumes 10 billion guesses/second (high-end GPU cluster).
        """
        if entropy_bits <= 0:
            return "instant"

        total_combinations = 2 ** entropy_bits
        seconds = total_combinations / guesses_per_second

        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 31_536_000:
            return f"{seconds / 86400:.0f} days"
        elif seconds < 31_536_000 * 1000:
            return f"{seconds / 31_536_000:.0f} years"
        elif seconds < 31_536_000 * 1e6:
            return f"{seconds / 31_536_000:.0e} years"
        else:
            return "millions of years+"

    @staticmethod
    def _has_sequential(password: str, min_run: int = 4) -> bool:
        """Check for sequential character runs (abc, 321)."""
        lower = password.lower()
        for seq in _SEQUENTIAL_PATTERNS:
            for i in range(len(lower) - min_run + 1):
                chunk = lower[i : i + min_run]
                if chunk in seq or chunk in seq[::-1]:
                    return True
        return False

    @staticmethod
    def _has_keyboard_walk(password: str, min_run: int = 4) -> bool:
        """Check for keyboard walk patterns (qwerty, asdf)."""
        lower = password.lower()
        for row in _KEYBOARD_ROWS:
            for i in range(len(lower) - min_run + 1):
                chunk = lower[i : i + min_run]
                if chunk in row or chunk in row[::-1]:
                    return True
        return False

    @staticmethod
    def _has_repeated_pattern(password: str) -> bool:
        """Detect repeating substrings (e.g., abcabc)."""
        n = len(password)
        if n < 6:
            return False
        for pattern_len in range(2, n // 2 + 1):
            pattern = password[:pattern_len]
            repetitions = n // pattern_len
            if pattern * repetitions == password[: pattern_len * repetitions]:
                if repetitions >= 2:
                    return True
        return False

    @staticmethod
    def _simulate_breach_check(password: str) -> bool:
        """Simulate a breach database lookup.

        In production, use the Have I Been Pwned k-anonymity API:
        https://haveibeenpwned.com/API/v3#PwnedPasswords

        This simulation hashes the password and checks against
        the common passwords list for demonstration purposes.
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        # Check against common list as a stand-in
        return password.lower() in _COMMON_PASSWORDS
