# Security policy

Please report vulnerabilities **privately** (GitHub "Report a vulnerability" under the Security tab, or email the
maintainer) rather than opening a public issue.

Design commitments (details in [docs/security-privacy.md](docs/security-privacy.md)):

* No credentials in the repository or config files; API keys come from environment variables only.
* The AI layer is off by default, needs explicit opt-in for any external provider, sends only a small redacted
  excerpt, and never executes anything it suggests.
* Do not commit real logs. Use the synthetic samples or sanitised data.
* The container runs as a non-root user.
