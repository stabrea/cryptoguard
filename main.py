#!/usr/bin/env python3
"""
CryptoGuard - Entry Point

Usage:
    python main.py <command> [options]
    python main.py --help

Commands:
    encrypt             Encrypt a file
    decrypt             Decrypt a file
    hash                Hash a file or string
    check-password      Analyze password strength
    generate-password   Generate a secure password
    generate-passphrase Generate a diceware-style passphrase
    keys                Key management operations
"""

from cryptoguard.cli import main

if __name__ == "__main__":
    main()
