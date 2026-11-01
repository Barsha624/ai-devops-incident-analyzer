# Detection rules

Each log event is checked against these rules. An event produces **at most one finding**. When several
rules match, the highest-priority one names the finding's *kind*, and **all** matching rule ids are
kept in the finding so the result stays explainable.

Priority: `HTTP_5XX` > `TIMEOUT` > `EXCEPTION` > `ERROR_LOG`.

| Rule id | Kind | Fires when | Deliberate exclusions |
|---|---|---|---|
| `R-HTTP-5XX` | `http_5xx` | the event carries an HTTP status 500-599 (structured field, access-log line, or a clear `status=`/`HTTP 502` cue in text) | `query returned 500 rows` is **not** a status: text needs an explicit cue |
| `R-TIMEOUT` | `timeout` | HTTP 408/504, **or** timeout wording (`timed out`, `ReadTimeout`, `deadline exceeded`, `ETIMEDOUT`) at WARN or above | INFO/DEBUG lines such as `timeout=30s` are ignored |
| `R-EXCEPTION` | `exception` | ERROR+ with an exception class name or a stack trace, **or** WARN+ with a stack trace | plain INFO text that merely mentions `Error` |
| `R-ERROR-LEVEL` | `error_log` | level is ERROR or CRITICAL and nothing more specific matched | WARN and below |
| `R-SPIKE` | (run-level, not a finding) | see below | |

## R-SPIKE: suspicious error spikes

1. Split the log's time range into fixed windows (default 60 s).
2. For each service, count **findings** per window (windows with none count as zero).
3. Baseline = the **median** per-window count (robust: the spike itself barely moves a median).
4. A window spikes when `count >= max(spike_min_count, spike_factor x max(baseline, 1))`
   (defaults: min 10, factor 3).
5. Consecutive spiking windows merge into one spike period, attached to overlapping incidents of the same service.

**Known weakness:** if errors fill most of the log, the median is itself high and real spikes can be missed.

## Signatures (what "the same error" means)

`signatures.normalize_message` replaces variable tokens with placeholders so repeated problems collapse:

```text
Timeout after 30001ms calling 10.0.3.7 for order 45784
-> Timeout after <n>ms calling <ip> for order <n>
```

UUIDs become `<uuid>`, IPv4 addresses `<ip>`, long hex strings `<hex>`, quoted strings `<str>`, numbers `<n>`.
HTTP findings use method + normalised path (`POST /orders/<id>/pay`), and exceptions use their class
name. Repeated signatures are what the report calls "repeated exceptions".

## Adding a rule (checklist)

1. Write the failing tests first (`tests/test_detection.py`), including at least one *negative* case.
2. Add `is_xxx(event)` and a rule id; extend `detect()` and `KIND_PRIORITY`.
3. Add the kind to `BASE_POINTS` in `severity.py` and to the docs tables.
4. Re-run `incident-analyzer evaluate ...` to check you did not break the labelled regression set.
