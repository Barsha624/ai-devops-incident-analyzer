# Supported log formats

The tool auto-detects the format **per line**, so mixed files work. Gzip (`.gz`) is read transparently.
Unrecognised lines are counted as *malformed*, sampled in the report, and never abort the run.

## 1. JSON Lines (one object per line) and JSON arrays

A file whose first non-blank character is `[` is read as one JSON array of objects (size-capped at 100 MB;
use JSON Lines for big files). Field names vary between loggers, so these aliases are accepted
(first match wins):

| Meaning | Accepted keys |
|---|---|
| timestamp | `timestamp`, `@timestamp`, `time`, `ts`, `datetime`, `date`, `asctime` |
| level | `level`, `severity`, `levelname`, `log_level`, `loglevel` |
| service | `service`, `service_name`, `app`, `application`, `component`, `logger`, `name` |
| message | `message`, `msg`, `error`, `exception`, `event`, `text` |
| stack trace | `stack`, `stack_trace`, `stacktrace`, `traceback`, `exc_info` |
| HTTP status | `status`, `status_code`, `http_status`, `statusCode` |
| method / path | `method`, `http_method`, `request_method` / `path`, `url`, `route`, `uri`, `request_path` |

Timestamps may be ISO-8601, `2026-10-31 09:30:00,123`, access-log style, or epoch seconds/ms/us/ns.
**Numeric levels are deliberately unsupported**: pino uses 50 for "error" while Python logging uses 50 for
"critical", so guessing would silently give wrong results.

## 2. Plain text, three shapes

```text
2026-10-31T09:30:00Z ERROR [checkout] upstream returned HTTP 502 for GET /x     (standard, [service] optional)
2026-10-31 09:30:00,123 - checkout - ERROR - upstream timed out                 (Python logging style)
203.0.113.9 - - [31/Oct/2026:09:30:00 +0000] "GET /x HTTP/1.1" 502 3026          (nginx / Apache access log)
```

Continuation lines (indented stack frames, `Traceback (most recent call last):`, `Caused by:`, a final
`SomeError: ...` line) attach to the previous record, which is how multi-line Python/Java traces stay
together. Only the first 40 lines are kept in full, but the **last** line is always remembered because for
Python tracebacks it names the exception.

## Service names

Taken from the record when present; otherwise from `service=...` in the message; otherwise from the file
name (`payments-api.log.gz` becomes `payments-api`); `--default-service` overrides the file-name fallback.

## Timezones

Timestamps with an offset are converted to UTC. **Timestamps without an offset are assumed to already be
UTC.** If your logs use local time without an offset, results will be shifted. See [limitations](limitations.md).

## Adding a format

Add a compiled regex to `text_parser.py` (compile at import time, not per line), return a `LogEvent`, and add
tests with a positive and a negative example.
