# Security Policy

## Reporting a Vulnerability

Please do **not** open a public GitHub issue with technical details for a suspected security vulnerability.

Use GitHub's **Private Vulnerability Reporting** for this repository instead:

- Go to the repository's **Security** tab.
- Select **Report a vulnerability**.
- Include the affected version, environment, proof of concept, impact, and any recommended mitigation.

If GitHub Private Vulnerability Reporting is unavailable for you, open a public issue that contains **no technical details** and asks for a private disclosure route.

## Scope

Security reports are in scope when they affect the confidentiality, integrity, or availability of users running Ghidra MCP, including:

- unintended command execution or script execution paths;
- path traversal or unsafe file access;
- unsafe exposure across Ghidra project, program, or server boundaries;
- bypasses of intended hardening, validation, or scope-boundary controls;
- denial-of-service conditions caused by malformed MCP requests or analysis inputs;
- vulnerabilities in release packaging, install scripts, or bridge/server communication.

Out of scope:

- issues that require already-compromised local administrator/root access without increasing impact;
- social engineering;
- spam or rate-limit-only reports;
- vulnerabilities only present in unsupported local modifications.

## Supported Versions

The latest released version and the `main` branch receive security review and fixes. Older releases may receive fixes when the issue is severe and the patch can be applied safely.

## Disclosure Process

After receiving a private report, the maintainer will aim to:

1. acknowledge the report;
2. reproduce and assess severity;
3. prepare a fix or mitigation;
4. coordinate disclosure timing with the reporter when appropriate;
5. publish release notes or an advisory once users have a safe upgrade path.

Please give the project reasonable time to investigate and remediate before public disclosure.
