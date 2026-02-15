# CryptoGuard

A cryptographic security toolkit providing file encryption, hashing utilities, password strength analysis, secure password generation, and encryption key management.

> **Security Notice:** This toolkit uses the well-audited [cryptography](https://cryptography.io/) library for all cryptographic operations. No homebrew cryptography is used. However, this project is built for educational and portfolio purposes. For production systems, have your security implementation reviewed by professionals and follow your organization's cryptographic standards.

## Features

### File Encryption (AES-256-GCM)
- Authenticated encryption with AES-256 in GCM mode
- Key derivation from passwords using PBKDF2-HMAC-SHA256 (600,000 iterations per OWASP guidelines)
- Fresh random salt and nonce per encryption (no IV reuse)
- Tamper detection via GCM authentication tag
- Best-effort secure file deletion (multi-pass overwrite)

### Hashing Utilities
- SHA-256, SHA-512, and BLAKE2b support
- Streaming file hashing for arbitrarily large files
- Constant-time hash comparison (timing attack resistant)
- Checksum file generation and verification (sha256sum-compatible format)

### Password Strength Analysis
- Shannon entropy calculation
- Character diversity scoring
- Common password detection (top breached passwords)
- Sequential character and keyboard walk detection
- Repeated pattern detection
- Brute-force crack time estimation
- Simulated breach database check
- Score from 0 (catastrophic) to 100 (excellent)

### Secure Password Generation
- Cryptographically random passwords (CSPRNG via `secrets` module)
- Configurable character sets with exclusion support
- Guaranteed character diversity (at least one from each enabled set)
- Diceware-style passphrase generation with 800+ word list
- Numeric PIN generation (for rate-limited interfaces only)

### Key Management
- AES-256 key generation and encrypted storage
- Master password protection for the key store
- Key rotation with audit trail
- Key revocation (destroys key material)
- Key export/import for secure transfer between machines

## Installation

```bash
# Clone the repository
git clone https://github.com/taofikbishi/cryptoguard.git
cd cryptoguard

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

## Usage

### Encrypt a File

```bash
# Encrypt (prompts for password)
python main.py encrypt secret.txt

# Encrypt with custom output path
python main.py encrypt secret.txt -o secret.txt.encrypted
```

### Decrypt a File

```bash
# Decrypt (prompts for password)
python main.py decrypt secret.txt.enc

# Decrypt with custom output path
python main.py decrypt secret.txt.enc -o restored.txt
```

### Hash a File or String

```bash
# Hash a file (default: SHA-256)
python main.py hash -f document.pdf

# Hash with SHA-512
python main.py hash -f document.pdf -a sha512

# Hash with BLAKE2b
python main.py hash -f document.pdf -a blake2b

# Hash a string
python main.py hash -s "Hello, World!"

# Hash and verify against expected value
python main.py hash -f document.pdf -v "expected_hash_here"
```

### Analyze Password Strength

```bash
# Analyze (secure prompt, no echo)
python main.py check-password

# Analyze directly (visible in shell history - use prompt for sensitive passwords)
python main.py check-password "MyP@ssw0rd123"
```

Output includes score (0-100), entropy, crack time estimate, warnings, and suggestions.

### Generate Passwords

```bash
# Generate a 20-character password (default)
python main.py generate-password

# Generate a 32-character password
python main.py generate-password -l 32

# Generate 5 passwords at once
python main.py generate-password -c 5

# Alphanumeric only (no special characters)
python main.py generate-password --no-special

# Exclude ambiguous characters
python main.py generate-password --exclude "0Ol1I"
```

### Generate Passphrases

```bash
# Generate a 5-word passphrase (default)
python main.py generate-passphrase

# Generate a 7-word passphrase with custom separator
python main.py generate-passphrase -w 7 -s "."

# Capitalized words, no appended number
python main.py generate-passphrase --capitalize --no-number
```

### Key Management

```bash
# Initialize a new key store (prompts for master password)
python main.py keys init

# Generate a new encryption key
python main.py keys generate

# Generate with a specific key ID
python main.py keys generate --key-id my-server-key

# List all keys
python main.py keys list

# Rotate a key (marks old as rotated, generates replacement)
python main.py keys rotate --key-id my-server-key

# Revoke a key (destroys key material)
python main.py keys revoke --key-id compromised-key

# Use a custom key store path
python main.py keys list --store /path/to/keystore.json
```

## Security Considerations

**Do's:**
- Use passwords with at least 80 bits of entropy for file encryption
- Use the password generator or passphrase generator for creating encryption passwords
- Keep your master password for the key store separate and strong
- Rotate keys periodically, especially if personnel with access change
- Verify file integrity after transfer using the hash verification feature

**Don'ts:**
- Do not use this toolkit as the sole security layer for sensitive production data without professional review
- Do not store encryption passwords alongside encrypted files
- Do not rely on `secure_delete` for SSD-based storage (use full-disk encryption instead)
- Do not use PINs as file encryption passwords (PINs are only for rate-limited interfaces)
- Do not pass sensitive passwords as CLI arguments in shared environments (use the secure prompt instead)

**Cryptographic Choices:**
| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| Encryption | AES-256-GCM | NIST-approved, authenticated encryption (confidentiality + integrity) |
| Key Derivation | PBKDF2-HMAC-SHA256 | OWASP recommended, 600K iterations |
| Hashing | SHA-256/512, BLAKE2b | SHA-2 family (NIST standard) + BLAKE2 (faster, equally secure) |
| Random Generation | `secrets` module | OS-level CSPRNG (cryptographically secure) |
| Hash Comparison | `hmac.compare_digest` | Constant-time to prevent timing side-channels |

## Architecture

```
cryptoguard/
    __init__.py          # Package init, public API exports
    encryptor.py         # AES-256-GCM file encryption/decryption
    hasher.py            # Hashing utilities and integrity verification
    password_analyzer.py # Password strength scoring and analysis
    password_generator.py # Secure password and passphrase generation
    key_manager.py       # Encrypted key storage and lifecycle management
    cli.py               # CLI interface (argparse + rich)
main.py                  # Entry point
```

**Data Flow:**
- `encryptor.py` handles all symmetric encryption via the `cryptography` library
- `key_manager.py` uses `encryptor.py` internally to protect stored keys
- `hasher.py` uses `hashlib` for hashing and `hmac` for constant-time comparison
- `password_analyzer.py` and `password_generator.py` are standalone modules
- `cli.py` wires everything together with a user-friendly interface using `rich`

## Requirements

- Python 3.10+
- [cryptography](https://cryptography.io/) >= 42.0.0
- [rich](https://rich.readthedocs.io/) >= 13.0.0

## License

MIT License - see [LICENSE](LICENSE) for details.
