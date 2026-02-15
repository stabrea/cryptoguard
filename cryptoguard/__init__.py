"""
CryptoGuard - A Cryptographic Security Toolkit

Provides file encryption, hashing utilities, password analysis,
secure password generation, and key management.

WARNING: This toolkit is for educational and portfolio purposes.
For production systems, use established security libraries directly
and have your implementation reviewed by security professionals.
Do NOT roll your own cryptography for production use.
"""

__version__ = "1.0.0"
__author__ = "Taofik Bishi"

from cryptoguard.encryptor import FileEncryptor
from cryptoguard.hasher import Hasher
from cryptoguard.password_analyzer import PasswordAnalyzer
from cryptoguard.password_generator import PasswordGenerator
from cryptoguard.key_manager import KeyManager

__all__ = [
    "FileEncryptor",
    "Hasher",
    "PasswordAnalyzer",
    "PasswordGenerator",
    "KeyManager",
]
