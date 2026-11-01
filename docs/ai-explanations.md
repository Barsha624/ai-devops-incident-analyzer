# Optional AI explanations

The core tool detects and scores incidents with deterministic rules. The AI layer is an **optional
add-on that reads the finished report** and drafts an explanation for a human. It cannot change what was
detected, how severe it is, or what the evidence says.

## Turning it on and off

| You want | Do |
|---|---|
| AI off (the default) | nothing |
| Try the pipeline with no network and no key | `--ai --ai-provider offline` |
| See exactly what would be sent, send nothing | `--ai-dry-run --ai-provider anthropic` |
| Use an external provider | `export ANTHROPIC_API_KEY=...` then `--ai --ai-provider anthropic --allow-external-ai` |
| Use a local model (data stays on your machine) | `--ai --ai-provider openai-compatible --ai-base-url http://localhost:11434/v1 --ai-model <local model>` |
| Disable AI completely, whatever flags/config say | `export INCIDENT_ANALYZER_DISABLE_AI=1` (status becomes `disabled`) |

Keys are read **only** from the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`), never from the config file.

## What is sent

Built in `ai/payload.py`, from the report, never from raw files:

* verified numbers: severity, score, severity reasons, counts, kinds, first/last seen, spike windows
* up to `max_evidence_per_incident` evidence excerpts per incident, each **redacted** and cut to 300 chars
* signatures (already normalised), redacted
* at most `max_incidents` incidents, most severe first

Not sent: file paths, host names from the filesystem, any line beyond the evidence limit, API keys.
`--ai-dry-run` prints the exact request so you can review it. See [security-privacy.md](security-privacy.md)
for the limits of redaction: it is best-effort, so use synthetic or already-sanitised logs.

## How facts are separated from hypotheses

The system prompt requires this structure, and `validate_output` enforces it:

| Field | Meaning | Enforcement |
|---|---|---|
| `observed_facts[]` | restates what the evidence shows | each needs `evidence_ids` that we actually supplied; otherwise **dropped** (`dropped.ungrounded_facts`) |
| `hypotheses[]` | possible explanations | `confidence` must be low/medium/high (anything else becomes `low`); citations are filtered to supplied ids; no valid citation means `grounded: false` |
| `investigation_steps[]` | what a human could check | read-only only: steps that look state-changing (restart, delete, terminate, scale, rollback, `rm -`, ...) are **dropped** (`dropped.unsafe_steps`) |
| `caveats[]` | limits of the explanation | free text, length-capped |

Additional guarantees:

* **Severity is not an AI field.** The schema has no severity; extra fields the model invents are discarded.
  `explain()` never mutates the report; the result is stored under `report["ai"]` only.
  (`test_explain_ok_with_fake_provider_and_severity_is_untouched`, `test_offline_ai_adds_a_separate_section_and_keeps_severity`)
* **Nothing is executed.** There is no code path from model text to a shell, an API call, or a file write.
* **Logs are untrusted data.** The prompt tells the model to treat excerpts as data (prompt-injection
  defence) and JSON escaping keeps log text inside its field. This reduces the risk; it cannot eliminate it,
  which is why the output is validated and never acted on automatically.
* **A bad answer is contained.** Invalid JSON, wrong shape, rate limits, timeouts, auth errors, a missing
  key: all produce `ai.status = "failed"` with a message. The analysis and exit code are unaffected.

## Failure handling

| Situation | Behaviour |
|---|---|
| HTTP 429 | retry with `Retry-After` (or exponential backoff 1 s, 2 s, ...), capped at 60 s, up to `max_retries` |
| HTTP 5xx, network error, timeout | same retry policy |
| HTTP 400/401/403/404 | no retry (it cannot help); clear message, key never echoed |
| Non-JSON / wrong-schema reply | `failed` with the reason |
| External provider without consent | `blocked`, nothing sent |
| No API key | `failed`: "ANTHROPIC_API_KEY is not set" |

## Providers

`ai/providers.py` defines a tiny interface, `complete(system, user, max_tokens) -> Completion`, because
that is all the rest of the code needs. Implementations: `OfflineProvider` (templates, no model),
`AnthropicProvider` (Messages API), `OpenAICompatibleProvider` (any `/chat/completions` server, including
local ones). HTTP uses the standard library, so there is no SDK dependency. A provider abstraction earns
its place here because the *privacy* story (local vs external) depends on swapping providers.

## Cost

One request per run (never one per log line). The size is bounded by configuration:

```text
input  tokens  ~  (system prompt + payload) / 4        # shown as estimated_input_tokens
output tokens  <=  ai.max_tokens                       # default 1200
cost per run   =   input_tokens x input_price + output_tokens x output_price
```

* For the bundled synthetic samples (4 incidents) a dry run estimates about **2,500 input tokens**
  (a rough characters / 4 estimate, not a tokenizer count).
* Prices differ by provider and model and change over time, so this repository does not quote them.
  Look up your provider's current pricing page and plug the numbers into the formula above.
* To reduce cost: lower `max_incidents` / `max_evidence_per_incident` / `max_tokens`, use a smaller model,
  or use a local model (no per-token fee, but you pay for hardware).
* After a real call, `ai.usage.input_tokens` / `output_tokens` report what the provider billed for.

## Testing without spending anything

`tests/test_ai.py` uses a fake provider and a scripted fake HTTP layer to test redaction, schema
validation, retries, rate limits, consent and the kill switch. No test calls a real API.

## Evaluating AI quality (do not skip this if you claim it is good)

Unit tests prove the *guard rails* work, not that the explanations are *useful*. To evaluate usefulness:
take 20+ past incidents where the real root cause is known, sanitise the logs, generate explanations, and
have a person score each hypothesis against the known cause (correct / plausible / misleading) with a fixed
rubric. Report the counts, the model, the prompt version and the date. Do not publish a number you did not
measure this way.
