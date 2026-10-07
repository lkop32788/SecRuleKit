# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Maintainer

**[@lkop32788](https://github.com/lkop32788)** is the designated security maintainer for SecRuleKit. All security reports are triaged and responded to by this maintainer.

Contact: long544844@gmail.com  
PGP: See [docs/pgp-key.asc](docs/pgp-key.asc)

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

SecRuleKit processes rule files (YARA, Sigma, Suricata) that may come from untrusted sources. A vulnerability in the parser could allow a crafted rule file to cause denial-of-service, path traversal, or in severe cases arbitrary code execution in the consuming process.

### How to Report

1. **Email:** Send details to `long544844@gmail.com` with subject line `[SecRuleKit Security] <brief description>`
2. **GitHub Private Advisory:** Use [GitHub's private vulnerability reporting](https://github.com/lkop32788/SecRuleKit/security/advisories/new) (preferred for coordinated disclosure)

### What to Include

- SecRuleKit version affected
- Python version and OS
- Proof-of-concept rule file (attach as `.txt` to avoid triggering AV)
- Steps to reproduce
- Impact assessment (DoS, information disclosure, code execution, etc.)

### Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgement | 48 hours |
| Initial triage | 5 business days |
| Patch (critical/high) | 14 days |
| Patch (medium/low) | 30 days |
| CVE assignment | Within 7 days of confirmed vulnerability |

### Coordinated Disclosure

We follow a **90-day coordinated disclosure** policy. After a patch is released (or 90 days have passed, whichever comes first), you are free to publish your findings. We will credit you in the release notes and CHANGELOG unless you request otherwise.

## Scope

**In scope:**

- Parser vulnerabilities (YARA, Sigma, Suricata/Snort): ReDoS, XXE, path traversal, memory exhaustion via crafted rule files
- Converter vulnerabilities: template injection, output injection
- CLI vulnerabilities: argument injection, arbitrary file write
- Dependency vulnerabilities affecting SecRuleKit's attack surface

**Out of scope:**

- Vulnerabilities in detection rules themselves (YARA/Sigma rule content)
- Issues requiring physical access or social engineering
- Third-party services or infrastructure not maintained by this project

## Security Advisories

Published advisories are listed at: https://github.com/lkop32788/SecRuleKit/security/advisories

## Acknowledgements

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities. Reporters of confirmed vulnerabilities will be listed in [CHANGELOG.md](CHANGELOG.md) and the corresponding GitHub Security Advisory.
