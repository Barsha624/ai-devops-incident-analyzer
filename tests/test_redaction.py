import pytest

from incident_analyzer.redaction import redact_report, redact_text, redact_with_counts


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("login failed for alice@example.com", "alice@example.com"),
        ("connect to 203.0.113.57 failed", "203.0.113.57"),
        ("key AKIAIOSFODNN7EXAMPLE rejected", "AKIAIOSFODNN7EXAMPLE"),
        ("Authorization: Bearer abcdefghijklmnop12345", "abcdefghijklmnop12345"),
        ("password=hunter2hunter2", "hunter2hunter2"),
        ('{"api_key": "sk-test-1234567890"}', "sk-test-1234567890"),
        ("postgres://app:s3cr3tpass@db.internal/app", "s3cr3tpass"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456", "eyJzdWIi"),
        ("card 4111 1111 1111 1111 declined", "4111 1111 1111 1111"),
        ("token abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
    ],
)
def test_secret_is_removed(text, secret):
    assert secret not in redact_text(text)
    assert "[REDACTED" in redact_text(text)


def test_ordinary_text_is_untouched():
    text = "2026-10-31 09:12:05 ERROR payments: connection timed out after 30001ms (order 45784)"
    assert redact_text(text) == text


def test_order_numbers_that_fail_luhn_are_not_treated_as_cards():
    assert redact_text("order 1234567890123 shipped") == "order 1234567890123 shipped"


def test_counts_report_what_was_replaced():
    _, counts = redact_with_counts("a@example.com b@example.com 203.0.113.1")
    assert counts["email"] == 2 and counts["ip"] == 1


def test_key_value_keeps_the_key_name():
    assert redact_text("password=abc12345") == "password=[REDACTED:secret]"


def test_redact_report_only_touches_free_text_fields():
    report = {
        "incidents": [
            {
                "id": "INC-001",
                "title": "svc: failed for bob@example.com",
                "first_seen": "2026-10-31T09:00:00Z",
                "evidence": [{"excerpt": "ip 203.0.113.9", "line": 3}],
                "top_signatures": [{"signature": "user <str> x@example.com", "count": 2}],
            }
        ]
    }
    redact_report(report)
    incident = report["incidents"][0]
    assert "bob@example.com" not in incident["title"]
    assert "203.0.113.9" not in incident["evidence"][0]["excerpt"]
    assert "x@example.com" not in incident["top_signatures"][0]["signature"]
    assert incident["id"] == "INC-001" and incident["first_seen"] == "2026-10-31T09:00:00Z"
    assert incident["evidence"][0]["line"] == 3
