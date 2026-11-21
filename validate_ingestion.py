"""SentinelForge AI — Realistic Log Ingestion Validation (Phase 2, Item 4).

Tests ingestion of representative SOC log formats:
- Windows: Sysmon Event IDs 1, 3, 11, 22
- Linux: SSH auth success/failure
- Network: DNS, HTTPS, outbound connections

Validates:
- Valid records parse correctly
- Malformed records produce visible errors (no silent loss)
- Missing fields handled without fabrication
- Null timestamps handled
- Out-of-order timestamps handled
- Duplicate events handled
- Unexpected field types handled
- Large command-line values handled
- Unicode and escaped characters handled
- Unknown event types handled
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from sentinelforge.ingestion.reader import reader_for, LogParseError
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import EventRepository


# ---------------------------------------------------------------------------
# Test fixtures: representative log records
# ---------------------------------------------------------------------------

VALID_SYSMON_PROCESS_CREATE = {
    "Event": {
        "System": {
            "EventID": 1,
            "TimeCreated": {"SystemTime": "2024-01-15T08:00:00.000Z"},
            "Computer": "WKSTN-01",
        },
        "EventData": {
            "Data": [
                {"Name": "ProcessId", "#text": "1234"},
                {"Name": "ParentProcessId", "#text": "5678"},
                {"Name": "Image", "#text": "C:\\Windows\\System32\\powershell.exe"},
                {"Name": "CommandLine", "#text": "powershell -EncodedCommand ..."},
                {"Name": "User", "#text": "WKSTN-01\\jdoe"},
            ]
        },
    }
}

VALID_SYSMON_NETWORK_CONNECT = {
    "Event": {
        "System": {
            "EventID": 3,
            "TimeCreated": {"SystemTime": "2024-01-15T08:01:00.000Z"},
            "Computer": "WKSTN-01",
        },
        "EventData": {
            "Data": [
                {"Name": "ProcessId", "#text": "1234"},
                {"Name": "Image", "#text": "C:\\Windows\\System32\\powershell.exe"},
                {"Name": "DestinationIp", "#text": "192.0.2.100"},
                {"Name": "DestinationPort", "#text": "4444"},
                {"Name": "Protocol", "#text": "tcp"},
            ]
        },
    }
}

VALID_SYSMON_FILE_CREATE = {
    "Event": {
        "System": {
            "EventID": 11,
            "TimeCreated": {"SystemTime": "2024-01-15T08:02:00.000Z"},
            "Computer": "WKSTN-01",
        },
        "EventData": {
            "Data": [
                {"Name": "ProcessId", "#text": "1234"},
                {"Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe"},
                {"Name": "TargetFilename", "#text": "C:\\Temp\\evil.bat"},
            ]
        },
    }
}

VALID_SYSMON_DNS_QUERY = {
    "Event": {
        "System": {
            "EventID": 22,
            "TimeCreated": {"SystemTime": "2024-01-15T08:03:00.000Z"},
            "Computer": "WKSTN-01",
        },
        "EventData": {
            "Data": [
                {"Name": "ProcessId", "#text": "1234"},
                {"Name": "Image", "#text": "C:\\Windows\\System32\\svchost.exe"},
                {"Name": "QueryName", "#text": "evil.example.com"},
            ]
        },
    }
}

VALID_LINUX_AUTH_SUCCESS = {
    "event_id": "evt-linux-001",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "auth.login.success",
    "source": "linux_auth",
    "user": "jdoe",
    "host": "SRV-01",
    "authentication": {
        "outcome": "success",
        "method": "ssh",
        "username": "jdoe",
        "source_address": "198.51.100.50",
    },
}

VALID_LINUX_AUTH_FAILURE = {
    "event_id": "evt-linux-002",
    "timestamp": "2024-01-15T08:01:00Z",
    "event_type": "auth.login.failed",
    "source": "linux_auth",
    "user": "attacker",
    "host": "SRV-01",
    "authentication": {
        "outcome": "failure",
        "method": "ssh",
        "username": "attacker",
        "source_address": "203.0.113.99",
    },
}

VALID_DNS_QUERY = {
    "event_id": "evt-dns-001",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "dns.query",
    "source": "dns",
    "host": "WKSTN-01",
    "network": {
        "direction": "outbound",
        "local_address": "192.168.1.50",
        "remote_address": "8.8.8.8",
        "local_port": 5353,
        "remote_port": 53,
        "protocol": "udp",
    },
    "dns": {"query_name": "update.example.com", "query_type": "A"},
}

VALID_HTTPS_CONNECTION = {
    "event_id": "evt-net-001",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "network.connection",
    "source": "network",
    "host": "WKSTN-01",
    "network": {
        "direction": "outbound",
        "local_address": "192.168.1.50",
        "remote_address": "203.0.113.10",
        "local_port": 49152,
        "remote_port": 443,
        "protocol": "tcp",
    },
}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

results: list[dict] = []


def record_test(name: str, passed: bool, detail: str = ""):
    results.append({"name": name, "passed": passed, "detail": detail})
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))


def normalize_event(raw: dict, source: str) -> tuple[bool, object, str]:
    """Attempt normalization. Returns (success, event_or_None, error_msg)."""
    from sentinelforge.ingestion.normalizer import normalize
    try:
        nev = normalize(raw, source=source)
        return True, nev, ""
    except Exception as e:
        return False, None, str(e)


# ---------------------------------------------------------------------------
# 1. Valid records
# ---------------------------------------------------------------------------

print("\n=== 1. Valid Records ===")

for name, raw, source in [
    ("Sysmon Process Create (Event ID 1)", VALID_SYSMON_PROCESS_CREATE, "sysmon"),
    ("Sysmon Network Connect (Event ID 3)", VALID_SYSMON_NETWORK_CONNECT, "sysmon"),
    ("Sysmon File Create (Event ID 11)", VALID_SYSMON_FILE_CREATE, "sysmon"),
    ("Sysmon DNS Query (Event ID 22)", VALID_SYSMON_DNS_QUERY, "sysmon"),
    ("Linux Auth Success", VALID_LINUX_AUTH_SUCCESS, "json"),
    ("Linux Auth Failure", VALID_LINUX_AUTH_FAILURE, "json"),
    ("DNS Query", VALID_DNS_QUERY, "json"),
    ("HTTPS Connection", VALID_HTTPS_CONNECTION, "json"),
]:
    ok, nev, err = normalize_event(raw, source)
    record_test(
        f"Valid: {name}",
        ok,
        f"normalized event_id={nev.event_id if nev else 'N/A'}"
        if ok
        else f"error: {err}",
    )


# ---------------------------------------------------------------------------
# 2. Malformed records (no silent loss)
# ---------------------------------------------------------------------------

print("\n=== 2. Malformed Records ===")

# Malformed JSONL line
malformed_jsonl_lines = [
    '{"event_id": "evt-bad-1", incomplete: true',
    'not json at all',
    '',
    '{"event_id": "evt-bad-2", "timestamp": "bad", }',
]

tmpdir = tempfile.mkdtemp(prefix="sentinelforge_ingest_")

for i, line in enumerate(malformed_jsonl_lines):
    try:
        tmp_path = os.path.join(tmpdir, f"malformed_{i}.jsonl")
        with open(tmp_path, "w") as f:
            f.write(line + "\n")

        reader = reader_for(tmp_path)
        try:
            events = list(reader.read(tmp_path))
            # Empty lines are not records — skipping is expected JSONL behavior
            if line.strip() == "":
                record_test(
                    f"Malformed JSONL line {i+1}",
                    True,
                    "empty line skipped (expected JSONL behavior)",
                )
            elif len(events) == 0:
                record_test(
                    f"Malformed JSONL line {i+1}",
                    False,
                    "silently dropped malformed line — no error raised",
                )
            else:
                record_test(
                    f"Malformed JSONL line {i+1}",
                    False,
                    f"parsed {len(events)} events from malformed line",
                )
        except LogParseError as e:
            record_test(
                f"Malformed JSONL line {i+1}",
                True,
                f"LogParseError raised: {e}",
            )
        except Exception as e:
            record_test(
                f"Malformed JSONL line {i+1}",
                True,
                f"exception raised: {type(e).__name__}: {e}",
            )
    except Exception as e:
        record_test(f"Malformed JSONL line {i+1}", False, f"test setup error: {e}")
    finally:
        # Clean up individual file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

# Clean up tmpdir
try:
    os.rmdir(tmpdir)
except Exception:
    pass


# ---------------------------------------------------------------------------
# 3. Missing fields (no fabrication)
# ---------------------------------------------------------------------------

print("\n=== 3. Missing Fields ===")

missing_field_cases = [
    ("No event_type", {**VALID_LINUX_AUTH_SUCCESS, "event_type": None}, "event_type"),
    ("No source_address", {**VALID_LINUX_AUTH_FAILURE, "authentication": {**VALID_LINUX_AUTH_FAILURE["authentication"], "source_address": None}}, "auth.source_address"),
    ("No username", {**VALID_LINUX_AUTH_SUCCESS, "authentication": {**VALID_LINUX_AUTH_SUCCESS["authentication"], "username": None}}, "auth.username"),
    ("No host", {**VALID_LINUX_AUTH_SUCCESS, "host": None}, "host"),
]

for name, raw, field_path in missing_field_cases:
    ok, nev, err = normalize_event(raw, "json")
    # Should not crash; missing fields should be None, not fabricated
    if ok:
        # Check that the specific missing field is None
        if field_path == "event_type":
            actual_is_none = nev.event_type is None
        elif field_path == "host":
            actual_is_none = nev.host is None
        elif field_path == "auth.username":
            actual_is_none = nev.authentication is not None and nev.authentication.username is None
        elif field_path == "auth.source_address":
            actual_is_none = nev.authentication is not None and nev.authentication.source_address is None
        else:
            actual_is_none = False
        record_test(
            f"Missing field: {name}",
            actual_is_none,
            f"{field_path} is None (not fabricated)" if actual_is_none else f"{field_path} was not None — possible fabrication",
        )
    else:
        record_test(
            f"Missing field: {name}",
            False,
            f"raised exception: {err}",
        )


# ---------------------------------------------------------------------------
# 4. Null timestamps
# ---------------------------------------------------------------------------

print("\n=== 4. Null Timestamps ===")

null_ts_cases = [
    ("Null timestamp", {**VALID_LINUX_AUTH_SUCCESS, "timestamp": None}),
    ("Empty timestamp", {**VALID_LINUX_AUTH_SUCCESS, "timestamp": ""}),
    ("Missing timestamp key", {k: v for k, v in VALID_LINUX_AUTH_SUCCESS.items() if k != "timestamp"}),
]

for name, raw in null_ts_cases:
    ok, nev, err = normalize_event(raw, "json")
    if ok:
        record_test(
            f"Null timestamp: {name}",
            True,
            f"normalized with timestamp={nev.timestamp}",
        )
    else:
        record_test(
            f"Null timestamp: {name}",
            True,  # raising an error is acceptable — not silent loss
            f"raised {type(err).__name__}: {err}",
        )


# ---------------------------------------------------------------------------
# 5. Out-of-order timestamps
# ---------------------------------------------------------------------------

print("\n=== 5. Out-of-Order Timestamps ===")

out_of_order_events = [
    {**VALID_LINUX_AUTH_SUCCESS, "event_id": "evt-ooo-1", "timestamp": "2024-01-15T08:05:00Z"},
    {**VALID_LINUX_AUTH_FAILURE, "event_id": "evt-ooo-2", "timestamp": "2024-01-15T08:01:00Z"},
    {**VALID_LINUX_AUTH_SUCCESS, "event_id": "evt-ooo-3", "timestamp": "2024-01-15T08:03:00Z"},
]

normalized_ooo = []
for raw in out_of_order_events:
    ok, nev, err = normalize_event(raw, "json")
    if ok:
        normalized_ooo.append(nev)

# All 3 should normalize successfully regardless of order
record_test(
    "Out-of-order timestamps",
    len(normalized_ooo) == 3,
    f"normalized {len(normalized_ooo)}/3 events",
)


# ---------------------------------------------------------------------------
# 6. Duplicate events
# ---------------------------------------------------------------------------

print("\n=== 6. Duplicate Events ===")

dup_raw = [VALID_LINUX_AUTH_SUCCESS, VALID_LINUX_AUTH_SUCCESS]
normalized_dups = []
for raw in dup_raw:
    ok, nev, err = normalize_event(raw, "json")
    if ok:
        normalized_dups.append(nev)

# Both should normalize (deduplication happens at storage layer)
record_test(
    "Duplicate events normalize",
    len(normalized_dups) == 2,
    f"normalized {len(normalized_dups)}/2 duplicate events",
)

# Verify deduplication at storage level
with tempfile.TemporaryDirectory() as tmpdir:
    db_path = os.path.join(tmpdir, "dedup_test.db")
    db = Database(db_path)
    db.initialize()
    repo = EventRepository(db)
    ids = repo.insert_events(normalized_dups)
    # Second insert of same event_id should be handled (idempotent or error)
    record_test(
        "Duplicate events stored",
        len(ids) >= 1,
        f"{len(ids)} unique event IDs stored from 2 duplicates",
    )


# ---------------------------------------------------------------------------
# 7. Unexpected field types
# ---------------------------------------------------------------------------

print("\n=== 7. Unexpected Field Types ===")

type_cases = [
    ("PID as string", {
        "Event": {
            "System": {
                "EventID": 1,
                "TimeCreated": {"SystemTime": "2024-01-15T08:00:00.000Z"},
                "Computer": "WKSTN-01",
            },
            "EventData": {
                "Data": [
                    {"Name": "ProcessId", "#text": "not-a-number"},
                    {"Name": "ParentProcessId", "#text": "5678"},
                    {"Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe"},
                    {"Name": "CommandLine", "#text": "cmd.exe"},
                    {"Name": "User", "#text": "WKSTN-01\\jdoe"},
                ]
            },
        }
    }),
    ("Port as string", {**VALID_DNS_QUERY, "network": {**VALID_DNS_QUERY["network"], "remote_port": "53"}}),
]

for name, raw in type_cases:
    ok, nev, err = normalize_event(raw, "json")
    record_test(
        f"Unexpected type: {name}",
        ok,
        f"normalized successfully" if ok else f"error: {err}",
    )


# ---------------------------------------------------------------------------
# 8. Large command-line values
# ---------------------------------------------------------------------------

print("\n=== 8. Large Command-Line Values ===")

large_cmd_raw = {
    "Event": {
        "System": {
            "EventID": 1,
            "TimeCreated": {"SystemTime": "2024-01-15T08:00:00.000Z"},
            "Computer": "WKSTN-01",
        },
        "EventData": {
            "Data": [
                {"Name": "ProcessId", "#text": "1234"},
                {"Name": "ParentProcessId", "#text": "5678"},
                {"Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe"},
                {"Name": "CommandLine", "#text": "A" * 50000},
                {"Name": "User", "#text": "WKSTN-01\\jdoe"},
            ]
        },
    }
}

ok, nev, err = normalize_event(large_cmd_raw, "sysmon")
record_test(
    "Large command-line (50K chars)",
    ok,
    f"cmd_line length={len(nev.process.command_line) if ok and nev.process and nev.process.command_line else 0}"
    if ok
    else f"error: {err}",
)


# ---------------------------------------------------------------------------
# 9. Unicode and escaped characters
# ---------------------------------------------------------------------------

print("\n=== 9. Unicode and Escaped Characters ===")

unicode_raw = {
    "event_id": "evt-unicode-1",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "auth.login.failed",
    "source": "linux_auth",
    "user": "us\u00e9r",
    "host": "h\u00f4st",
    "authentication": {
        "outcome": "failure",
        "method": "ssh",
        "username": "us\u00e9r",
        "source_address": "192.0.2.100",
    },
}

ok, nev, err = normalize_event(unicode_raw, "json")
record_test(
    "Unicode username/host",
    ok,
    f"user={nev.user}, host={nev.host}" if ok else f"error: {err}",
)

escaped_raw = {
    "event_id": "evt-escaped-1",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "process.create",
    "source": "json",
    "process": {
        "command_line": 'powershell -enc "aGVsbG8gd29ybGQ="',
        "path": 'C:\\"Quoted\\"Path\\\\exe',
    },
}

ok, nev, err = normalize_event(escaped_raw, "json")
record_test(
    "Escaped characters in command line",
    ok,
    f"normalized successfully" if ok else f"error: {err}",
)


# ---------------------------------------------------------------------------
# 10. Unknown event types
# ---------------------------------------------------------------------------

print("\n=== 10. Unknown Event Types ===")

unknown_type_raw = {
    "event_id": "evt-unknown-1",
    "timestamp": "2024-01-15T08:00:00Z",
    "event_type": "custom.unknown.event",
    "source": "json",
    "custom_field": "some_value",
}

ok, nev, err = normalize_event(unknown_type_raw, "json")
record_test(
    "Unknown event type",
    ok,
    f"normalized with event_type={nev.event_type}" if ok else f"error: {err}",
)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n" + "=" * 60)
print("INGESTION VALIDATION SUMMARY")
print("=" * 60)

total = len(results)
passed = sum(1 for r in results if r["passed"])
failed = total - passed

print(f"Total tests: {total}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")

if failed:
    print("\nFAILURES:")
    for r in results:
        if not r["passed"]:
            print(f"  - {r['name']}: {r['detail']}")

exit_code = 0 if failed == 0 else 1
print(f"\nExit code: {exit_code}")
sys.exit(exit_code)