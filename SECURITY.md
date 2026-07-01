# Security Policy

## Reporting a vulnerability

**Please do not file security vulnerabilities as public GitHub issues.**

If you discover a security vulnerability in Lvau, please report it responsibly:

1. **Email**: Send a report to the maintainers via the email listed on the [GitHub profile](https://github.com/lasder-ca), or open a [private security advisory](https://github.com/lasder-ca/lvau/security/advisories/new) on GitHub.
2. **Include**:
   - A description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact
   - Suggested fix (if any)

## Scope

The following are in scope:

- Cryptographic implementation bugs in `lvau-core`
- Envelope format parsing vulnerabilities in `lvau-protocol`
- Key material leakage (memory, logs, filesystem)
- Authentication bypass
- Nonce or salt reuse bugs
- KDF parameter weakness

The following are **out of scope**:

- Denial-of-service via large files (known limitation)
- Weak passwords chosen by users
- Issues in third-party dependencies (report those upstream, but let us know)
- Social engineering

## Audit status

Lvau has **not been formally audited** by a third-party security firm. The cryptographic design uses standard, well-reviewed primitives (XChaCha20-Poly1305, Argon2id, HKDF-SHA256), but the implementation has not undergone professional review.

A formal audit is a goal for future releases.

## Expected response

- We aim to acknowledge reports within **7 days**
- We aim to provide a fix or mitigation plan within **30 days** for confirmed vulnerabilities
- We will credit reporters in the changelog unless they prefer to remain anonymous

## Responsible disclosure

We ask that you:

- Give us reasonable time to investigate and fix the issue before public disclosure
- Do not exploit the vulnerability beyond what is necessary to demonstrate it
- Do not access or modify other users' data

Thank you for helping keep Lvau secure.
