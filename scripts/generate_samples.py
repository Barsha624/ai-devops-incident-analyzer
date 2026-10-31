#!/usr/bin/env python3
"""Generate the synthetic sample logs in ``samples/``.

Everything is invented and the generator is seeded, so running it twice produces identical files.
Addresses use documentation-only ranges (203.0.113.0/24, 10.0.0.0/8) and e-mail addresses use
example.com. Nothing here comes from a real system.

The scripted story (all times UTC, 2026-10-31):

* 09:12-09:24  payments-worker exhausts its database connection pool (timeouts + a CRITICAL line)
* 09:13-09:25  checkout-api returns 502/504 because payments-worker is failing
* 09:13-09:25  web-frontend (nginx) serves 502s on the checkout route
* 09:35-09:38  inventory-service hits a KeyError bug after a (fictional) deploy
* 09:05        one isolated inventory-service error (too small to be an incident)
* A few deliberately broken lines to exercise malformed-line handling

Usage:  python scripts/generate_samples.py [output_dir]
"""

from __future__ import annotations

import json
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASE = datetime(2026, 10, 31, 9, 0, 0, tzinfo=UTC)
END_SECONDS = 45 * 60


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


def iso(seconds: float) -> str:
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(path: Path, rows: list[tuple[float, str]], tail: list[str] | None = None) -> None:
    rows.sort(key=lambda r: r[0])
    lines = [text for _, text in rows] + (tail or [])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


def web_frontend(rng: random.Random) -> list[tuple[float, str]]:
    """nginx access log (plain text). 502s on POST /api/checkout during the outage."""
    rows = []
    for second in range(0, END_SECONDS, 2):
        in_outage = 13 * 60 <= second < 25 * 60
        checkout = rng.random() < 0.25
        order_id = rng.randint(40000, 49999)
        if checkout:
            method, path = "POST", f"/api/checkout/{order_id}"
            status = 502 if in_outage and rng.random() < 0.6 else 201
        else:
            method, path = "GET", f"/api/products/{rng.randint(1, 300)}"
            status = 200
        stamp = at(second).strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"203.0.113.{rng.randint(1, 254)}"
        size = rng.randint(120, 4000)
        rows.append((second, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size}'))
    return rows


def checkout_api(rng: random.Random) -> tuple[list[tuple[float, str]], list[str]]:
    """JSON Lines application log."""
    rows = []
    for second in range(0, END_SECONDS, 4):
        record = {
            "timestamp": iso(second),
            "level": "info",
            "service": "checkout-api",
            "message": "order created",
            "method": "POST",
            "path": f"/orders/{rng.randint(40000, 49999)}",
            "status": 201,
            "duration_ms": rng.randint(40, 400),
        }
        rows.append((second, json.dumps(record)))

    for second in range(13 * 60, 25 * 60, 6):
        order = rng.randint(40000, 49999)
        status = rng.choice([502, 502, 504])
        record = {
            "timestamp": iso(second),
            "level": "error",
            "service": "checkout-api",
            "message": f"upstream payments-worker returned HTTP {status}",
            "method": "POST",
            "path": f"/orders/{order}/pay",
            "status": status,
        }
        rows.append((second, json.dumps(record)))

    for second in range(13 * 60 + 3, 25 * 60, 20):
        record = {
            "timestamp": iso(second),
            "level": "warning",
            "service": "checkout-api",
            "message": f"request to payments-worker timed out after {rng.randint(29900, 30100)}ms",
        }
        rows.append((second, json.dumps(record)))

    # A line that deliberately contains fake personal data, so the AI sanitiser has work to do.
    rows.append(
        (
            16 * 60 + 40,
            json.dumps(
                {
                    "timestamp": iso(16 * 60 + 40),
                    "level": "error",
                    "service": "checkout-api",
                    "message": (
                        "payment failed for jane.doe@example.com from 203.0.113.50 "
                        "api_key=not-a-real-key Authorization: Bearer fake.example.token"
                    ),
                }
            ),
        )
    )

    broken = [
        '{"timestamp": "2026-10-31T09:20:11Z", "level": "err',  # truncated write
        "-- log rotated --",
    ]
    return rows, broken


def payments_worker(rng: random.Random) -> tuple[list[tuple[float, str]], list[str]]:
    """Python ``logging`` default style with multi-line tracebacks."""
    rows = []

    def stamp(second: float) -> str:
        return at(second).strftime("%Y-%m-%d %H:%M:%S") + f",{rng.randint(0, 999):03d}"

    for second in range(0, END_SECONDS, 10):
        if 12 * 60 <= second < 24 * 60:
            continue
        batch = rng.randint(5, 30)
        rows.append(
            (second, f"{stamp(second)} - payments-worker - INFO - processed batch size={batch}")
        )

    for second in range(12 * 60 + 5, 24 * 60, 15):
        order = rng.randint(40000, 49999)
        text = "\n".join(
            [
                f"{stamp(second)} - payments-worker - ERROR - Failed to charge order {order}: "
                "connection timed out",
                "Traceback (most recent call last):",
                '  File "/app/payments/charge.py", line 88, in charge',
                "    conn = pool.acquire()",
                "sqlalchemy.exc.TimeoutError: QueuePool limit of size 5 overflow 10 reached, "
                "connection timed out, timeout 30.00",
            ]
        )
        rows.append((second, text))

    rows.append(
        (
            20 * 60,
            f"{stamp(20 * 60)} - payments-worker - CRITICAL - consumer pool exhausted, "
            "restarting worker",
        )
    )
    rows.append(
        (
            24 * 60 + 30,
            f"{stamp(24 * 60 + 30)} - payments-worker - INFO - connection pool recovered",
        )
    )
    return rows, ["Segmentation note: stderr line without a timestamp"]


def inventory_service(rng: random.Random) -> list[tuple[float, str]]:
    """Standard text format with a bracketed service name."""
    rows = []
    for second in range(0, END_SECONDS, 15):
        rows.append(
            (
                second,
                f"{iso(second)} INFO [inventory-service] stock sync ok items={rng.randint(10, 90)}",
            )
        )
    rows.append(
        (5 * 60, f"{iso(5 * 60)} ERROR [inventory-service] cache refresh failed, will retry")
    )
    for second in (35 * 60 + 10, 35 * 60 + 55, 36 * 60 + 40, 37 * 60 + 20, 37 * 60 + 58):
        text = "\n".join(
            [
                f"{iso(second)} ERROR [inventory-service] Unhandled exception in /stock/sync",
                "Traceback (most recent call last):",
                '  File "/app/inventory/sync.py", line 41, in sync_item',
                "    sku = payload['sku']",
                "KeyError: 'sku'",
            ]
        )
        rows.append((second, text))
    return rows


def healthy_service(rng: random.Random) -> list[tuple[float, str]]:
    """A quiet log: should produce no incidents."""
    return [
        (
            second,
            f"{iso(second)} INFO [reports-service] report generated id={rng.randint(1000, 9999)}",
        )
        for second in range(0, 10 * 60, 20)
    ]


def main() -> None:
    out = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parent.parent / "samples"
    )
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261031)

    write(out / "web-frontend.log", web_frontend(rng))
    rows, broken = checkout_api(rng)
    # Insert the broken lines mid-file so they are not just trailing noise.
    rows.sort(key=lambda r: r[0])
    texts = [t for _, t in rows]
    texts.insert(len(texts) // 2, broken[0])
    texts.insert(len(texts) // 3, broken[1])
    (out / "checkout-api.jsonl").write_text("\n".join(texts) + "\n", encoding="utf-8")
    print(f"wrote {out / 'checkout-api.jsonl'} ({len(texts)} lines)")

    rows, broken = payments_worker(rng)
    write(out / "payments-worker.log", rows, broken)
    write(out / "inventory-service.log", inventory_service(rng))
    write(out / "healthy-service.log", healthy_service(rng))


if __name__ == "__main__":
    main()
