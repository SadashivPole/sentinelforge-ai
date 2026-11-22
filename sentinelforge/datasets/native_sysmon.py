"""Native Sysmon-style event generator for TASK 6.

Produces genuine Sysmon EVTX-converted JSON events with the native
Event/System/EventData structure. These are NOT generic JSONL records —
they use the Sysmon XML-converted JSON schema that the SysmonReader expects.

Event IDs included:
- 1: Process Create
- 3: Network Connection
- 11: File Create
- 22: DNS Query
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Reserved test IP ranges (RFC 5737) and .example domains (RFC 2606)
TEST_IP_BLOCKS = ["192.0.2.", "198.51.100.", "203.0.113."]
EXAMPLE_DOMAINS = ["example.com", "example.org", "example.net"]

HOSTS = ["WKSTN-01", "WKSTN-02", "WKSTN-03", "SRV-01", "SRV-02", "DC-01", "LAPTOP-01"]
USERS = ["jdoe", "asmith", "rjohnson", "mwilliams", "sadmin", "jdev", "opsuser"]

PROCESS_NAMES = [
    "svchost.exe",
    "explorer.exe",
    "WINWORD.EXE",
    "EXCEL.EXE",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "mshta.exe",
    "cmd.exe",
    "notepad.exe",
    "chrome.exe",
    "firefox.exe",
    "EDRAgent.exe",
    "spoolsv.exe",
    "lsass.exe",
    "services.exe",
]

DEFAULT_START_TIME = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_ip(rng: random.Random) -> str:
    return f"{rng.choice(TEST_IP_BLOCKS)}{rng.randint(1, 254)}"


def _random_domain(rng: random.Random) -> str:
    return rng.choice(EXAMPLE_DOMAINS)


def _random_host(rng: random.Random) -> str:
    return rng.choice(HOSTS)


def _random_user(rng: random.Random) -> str:
    return rng.choice(USERS)


def _random_process(rng: random.Random) -> str:
    return rng.choice(PROCESS_NAMES)


def _data_item(name: str, value: str) -> dict[str, str]:
    """Build a Sysmon EventData Data item."""
    return {"Name": name, "#text": value}


def _sysmon_event(
    event_id: int,
    timestamp: str,
    computer: str,
    data_items: list[dict[str, str]],
    event_data_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a native Sysmon EVTX-converted JSON event.

    Structure:
        {
          "Event": {
            "System": {
              "Provider": {...},
              "EventID": 1,
              "TimeCreated": {"SystemTime": "..."},
              "Computer": "..."
            },
            "EventData": {
              "Data": [
                {"Name": "Image", "#text": "..."},
                ...
              ]
            }
          }
        }
    """
    return {
        "Event": {
            "System": {
                "Provider": {
                    "Name": "Microsoft-Windows-Sysmon",
                    "Guid": "{57709853-2263-4531-95CE-168E4D7F34C2}",
                },
                "EventID": event_id,
                "TimeCreated": {"SystemTime": timestamp},
                "Computer": computer,
            },
            "EventData": {
                "Data": data_items,
                **(event_data_extra or {}),
            },
        }
    }


def _process_create_event(
    rng: random.Random,
    timestamp: str,
    computer: str,
    suspicious: bool = False,
) -> dict[str, Any]:
    """Generate Sysmon Event ID 1: Process Create."""
    proc = _random_process(rng)
    user = _random_user(rng)
    pid = rng.randint(1000, 99999)
    ppid = rng.randint(1000, 99999)

    cmd_line = f"{proc} -legit-args"
    if suspicious and proc in ("powershell.exe", "pwsh.exe"):
        cmd_line = (
            f"{proc} -ExecutionPolicy Bypass -File C:\\\\Users\\\\{user}\\\\script.ps1"
        )

    data_items = [
        _data_item("RuleName", "ProcessCreateRule"),
        _data_item("User", user),
        _data_item("ProcessId", str(pid)),
        _data_item("Image", f"C:\\\\Windows\\\\System32\\\\{proc}"),
        _data_item("CommandLine", cmd_line),
        _data_item("ParentProcessId", str(ppid)),
        _data_item("ParentImage", "C:\\\\Windows\\\\System32\\\\services.exe"),
    ]

    return _sysmon_event(1, timestamp, computer, data_items)


def _network_connection_event(
    rng: random.Random,
    timestamp: str,
    computer: str,
    suspicious: bool = False,
) -> dict[str, Any]:
    """Generate Sysmon Event ID 3: Network Connection."""
    user = _random_user(rng)
    pid = rng.randint(1000, 99999)
    proc = _random_process(rng)

    if suspicious:
        dest = _random_ip(rng)
        port = str(rng.choice([4433, 8443, 8080, 9001]))
    else:
        dest = _random_domain(rng)
        port = "443"

    data_items = [
        _data_item("RuleName", "NetworkConnectRule"),
        _data_item("User", user),
        _data_item("ProcessId", str(pid)),
        _data_item("Image", f"C:\\\\Windows\\\\System32\\\\{proc}"),
        _data_item("Protocol", "tcp"),
        _data_item("DestinationAddress", dest),
        _data_item("DestinationPort", port),
        _data_item("Direction", "outbound"),
    ]

    return _sysmon_event(3, timestamp, computer, data_items)


def _file_create_event(
    rng: random.Random,
    timestamp: str,
    computer: str,
    suspicious: bool = False,
) -> dict[str, Any]:
    """Generate Sysmon Event ID 11: File Create."""
    user = _random_user(rng)
    pid = rng.randint(1000, 99999)
    proc = _random_process(rng)

    if suspicious:
        filename = f"C:\\\\Users\\\\{user}\\\\Downloads\\\\payload.ps1"
    else:
        filename = (
            f"C:\\\\Users\\\\{user}\\\\Documents\\\\file_{rng.randint(1, 9999)}.txt"
        )

    data_items = [
        _data_item("RuleName", "FileCreateRule"),
        _data_item("User", user),
        _data_item("ProcessId", str(pid)),
        _data_item("Image", f"C:\\\\Windows\\\\System32\\\\{proc}"),
        _data_item("TargetFilename", filename),
        _data_item("CreationTime", timestamp),
    ]

    return _sysmon_event(11, timestamp, computer, data_items)


def _dns_query_event(
    rng: random.Random,
    timestamp: str,
    computer: str,
    suspicious: bool = False,
) -> dict[str, Any]:
    """Generate Sysmon Event ID 22: DNS Query."""
    user = _random_user(rng)
    pid = rng.randint(1000, 99999)

    if suspicious:
        query = f"suspicious-{rng.randint(1000, 9999)}.example.com"
    else:
        query = f"www.{_random_domain(rng)}"

    data_items = [
        _data_item("RuleName", "DnsQueryRule"),
        _data_item("User", user),
        _data_item("ProcessId", str(pid)),
        _data_item("Image", "C:\\\\Windows\\\\System32\\\\dns.exe"),
        _data_item("QueryName", query),
        _data_item("QueryType", "A"),
        _data_item("QueryStatus", "0"),
    ]

    return _sysmon_event(22, timestamp, computer, data_items)


def generate_native_sysmon_events(
    count: int = 1000,
    seed: int = 42,
    start_time: datetime | None = None,
) -> list[dict[str, Any]]:
    """Generate native Sysmon-style events with mixed event IDs.

    Produces a mix of Event ID 1 (Process Create), 3 (Network Connection),
    11 (File Create), and 22 (DNS Query) events, some suspicious and some
    benign. Labels are NOT embedded in the events — they are stored
    separately in the ground truth manifest.
    """
    rng = random.Random(seed)
    start = start_time or DEFAULT_START_TIME
    events: list[dict[str, Any]] = []

    event_types = [
        (1, _process_create_event),
        (3, _network_connection_event),
        (11, _file_create_event),
        (22, _dns_query_event),
    ]

    for i in range(count):
        _event_id, generator = event_types[i % len(event_types)]
        ts = _iso(start + timedelta(seconds=rng.randint(0, 7 * 24 * 3600)))
        computer = _random_host(rng)
        suspicious = rng.random() < 0.3
        events.append(generator(rng, ts, computer, suspicious=suspicious))

    return events


def write_native_sysmon_jsonl(
    events: list[dict[str, Any]],
    output_path: str | Path,
) -> None:
    """Write native Sysmon events as JSONL (one EVTX-converted record per line)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(ev, ensure_ascii=False) + "\n" for ev in events)
