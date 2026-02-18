# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest release on the `master` branch receives security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in CryptoGuard, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

**Email:** [bishitaofik@gmail.com](mailto:bishitaofik@gmail.com)

Include in your report:

- A description of the vulnerability and its potential impact
- The affected cryptographic component (encryption, hashing, key management, password analysis, etc.)
- Steps to reproduce the issue
- Any proof-of-concept code, if applicable

### Cryptographic Issues

We take cryptographic vulnerabilities especially seriously. Reports in the following areas are high priority:

- Weaknesses in key derivation (PBKDF2 parameter handling, salt generation)
- IV/nonce reuse conditions in AES-GCM encryption
- Timing side-channels in hash comparison or password validation
- Insecure defaults or fallback to weak algorithms
- Flaws in secure file deletion logic
- Key material exposure through logging, error messages, or memory handling

## Response Timeline

| Action                     | Timeframe       |
|----------------------------|-----------------|
| Acknowledgment of report   | 48 hours        |
| Initial assessment         | 5 business days |
| Patch or mitigation issued | 30 days         |
| Public disclosure           | After patch     |

For critical cryptographic flaws (e.g., plaintext key exposure, nonce reuse), we aim to issue a patch within 7 days. We will coordinate disclosure timing with the reporter and provide credit unless anonymity is requested.

## Scope

The following are **in scope** for security reports:

- Cryptographic implementation flaws in any module
- Insecure handling of key material, passwords, or sensitive data
- Dependencies with known CVEs (especially the `cryptography` library)
- Command injection or path traversal via file operation inputs
- Information leakage through error messages or logs

The following are **out of scope**:

- Issues requiring physical access to the host machine
- Weaknesses in user-chosen passwords (that is the user's responsibility)
- Theoretical attacks that require infeasible computational resources
- The educational nature of the project (see README for production use caveats)

## Important Note

CryptoGuard is built for **educational and portfolio purposes**. It uses well-audited libraries (`cryptography.io`) and follows current best practices, but it has not undergone a formal security audit. For production cryptographic needs, consult a professional.
