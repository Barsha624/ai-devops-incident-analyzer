# Security and privacy

## What data are we dealing with?

Logs routinely contain things nobody meant to log: e-mail addresses, IP addresses, tokens in URLs,
passwords in stack traces, order or customer ids. Treat **logs, reports and metrics derived from them as
sensitive**. The safest log is one that was sanitised at the source.

## Defence in depth for the AI feature

No single control is trusted; each layer limits damage if another fails.

| Layer | Control |
|---|---|
| 1. Off by default | AI runs only with `--ai` / `[ai] enabled = true` |
| 2. Hard kill switch | `INCIDENT_ANALYZER_DISABLE_AI=1` overrides flags and config |
| 3. Local first | `offline` provider (no network) and local OpenAI-compatible servers are never "external" |
| 4. Explicit consent | external providers need `--allow-external-ai` / `allow_external = true`, even when a key is present |
| 5. Minimisation | only verified summary fields + a few short excerpts; never whole files or file paths |
| 6. Redaction | emails, IPv4, bearer tokens, JWTs, AWS access keys, `password=`/`token=`/`api_key=` pairs, URL credentials, private keys, Luhn-valid card numbers, long token-like strings |
| 7. Preview | `--ai-dry-run` shows the exact request and sends nothing |
| 8. Output validation | JSON schema, length caps, citation checks, state-changing steps dropped |
| 9. No execution | no code path turns model text into an action |
| 10. Separation | AI output cannot alter severity, counts, timestamps or evidence |

### What redaction cannot do

Regular expressions do not understand context. They will **miss**: personal names, postal addresses, phone
numbers, free-text secrets without a recognisable key name, internal hostnames, customer ids, and anything
in a format they were not written for. They can also over-redact. Therefore:

* use **synthetic or already-sanitised logs** for anything that leaves your machine;
* read the `--ai-dry-run` output before the first real call;
* check your provider's data-retention and training terms and your company policy before sending any
  production-derived text to an external service.

### Prompt injection

Log lines are attacker-influenced data (a user can put text in a User-Agent or an error message). A line like
`ignore previous instructions...` could reach the model. Mitigations: the prompt marks excerpts as untrusted
data; payload text is JSON-escaped; the model has no tools; output is validated and never executed. The residual
risk is a *misleading explanation*, which is why it is labelled "generated text, not verified" and why the
verified evidence ids are printed beside every claim.

## Secrets handling

* API keys: **environment variables only**, never the config file, never CLI arguments (those leak into
  shell history and process lists), never logged (`ai/providers.py` does not log headers or bodies).
* `.env`, `*.pem`, `*.key` are git-ignored and excluded from the Docker context; only `.env.example`
  (with empty values) is committed.
* The image contains **no keys**: pass them at run time (`-e ANTHROPIC_API_KEY`).
* If a key is ever committed: revoke it at the provider immediately, then remove it from history.
  Deleting it in a later commit does **not** make it safe.

## Runtime hardening

* The Docker image runs as a **non-root user** (uid 10001) on a slim base, with no build tools in the final stage.
* Mount logs **read-only** (`-v ./logs:/data:ro`). The tool only reads them.
* The metrics exporter binds `127.0.0.1` by default; use `--host 0.0.0.0` only inside a container and
  publish the port to localhost or a private network. It has no authentication, so do not expose it publicly.
* Zero runtime dependencies means a small supply-chain surface. Dev tools are pinned by minimum version;
  Dependabot is configured for actions, pip and Docker.

## AWS

Use the least privilege that works: `logs:FilterLogEvents` on the specific log group(s). Prefer instance
roles / SSO profiles over long-lived access keys. See [aws-cloudwatch.md](aws-cloudwatch.md). The tool is
read-only and never writes to AWS.

## Reports

Evidence excerpts are raw log text. Use `--redact` before sharing a report outside the team that owns the
logs.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
