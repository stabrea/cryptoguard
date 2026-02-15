"""Tests for the password analyzer module."""

from cryptoguard.password_analyzer import PasswordAnalyzer, PasswordReport


def test_weak_password_scores_low():
    report = PasswordAnalyzer.analyze("123456", check_breach=False)
    assert report.score < 30
    assert report.rating in ("Very Weak", "Weak")


def test_common_password_scores_very_low():
    report = PasswordAnalyzer.analyze("password", check_breach=False)
    assert report.score <= 5
    assert report.is_common is True


def test_strong_password_scores_high():
    report = PasswordAnalyzer.analyze("X#9kLm!2pQr$vB7n", check_breach=False)
    assert report.score >= 60
    assert report.rating in ("Strong", "Very Strong")


def test_very_strong_password():
    report = PasswordAnalyzer.analyze("Tr0ub4dor&3#Horse!Battery$Staple99", check_breach=False)
    assert report.score >= 80
    assert report.rating == "Very Strong"


def test_entropy_calculation_empty():
    entropy = PasswordAnalyzer.calculate_entropy("")
    assert entropy == 0.0


def test_entropy_calculation_digits_only():
    entropy = PasswordAnalyzer.calculate_entropy("1234")
    # 4 chars * log2(10) = ~13.29 bits
    assert 13.0 < entropy < 14.0


def test_entropy_calculation_mixed():
    entropy = PasswordAnalyzer.calculate_entropy("aA1!")
    # Pool: 26 + 26 + 10 + 33 = 95, entropy = 4 * log2(95) ~ 26.3
    assert 25.0 < entropy < 27.0


def test_entropy_increases_with_length():
    short = PasswordAnalyzer.calculate_entropy("aB1!")
    long = PasswordAnalyzer.calculate_entropy("aB1!aB1!aB1!")
    assert long > short


def test_report_has_character_sets():
    report = PasswordAnalyzer.analyze("aB3$", check_breach=False)
    assert "lowercase" in report.character_sets
    assert "uppercase" in report.character_sets
    assert "digits" in report.character_sets
    assert "special" in report.character_sets


def test_report_warnings_for_short_password():
    report = PasswordAnalyzer.analyze("ab", check_breach=False)
    warning_text = " ".join(report.warnings)
    assert "shorter than 8" in warning_text.lower() or "8 characters" in warning_text.lower()


def test_report_is_password_report_instance():
    report = PasswordAnalyzer.analyze("test123", check_breach=False)
    assert isinstance(report, PasswordReport)
    assert isinstance(report.score, int)
    assert 0 <= report.score <= 100
    assert isinstance(report.entropy_bits, float)


def test_score_clamped_between_0_and_100():
    # Very weak
    weak = PasswordAnalyzer.analyze("a", check_breach=False)
    assert 0 <= weak.score <= 100

    # Very strong
    strong = PasswordAnalyzer.analyze("Z$8mK!pL2qR#vN7xW&4jH", check_breach=False)
    assert 0 <= strong.score <= 100


def test_sequential_pattern_penalty():
    report = PasswordAnalyzer.analyze("abcdefgh", check_breach=False)
    warning_text = " ".join(report.warnings).lower()
    assert "sequential" in warning_text


def test_keyboard_walk_penalty():
    report = PasswordAnalyzer.analyze("qwertyui", check_breach=False)
    warning_text = " ".join(report.warnings).lower()
    assert "keyboard" in warning_text
