"""Synthetic enterprise SOC dataset generator.

Produces reproducible synthetic security events across multiple log sources:
Windows Sysmon, Linux authentication, Firewall, DNS, and Network — plus
correlated attack scenarios. Ground-truth labels are stored separately from
raw events to prevent data leakage.

All generation uses a fixed random seed for reproducibility. Events use nested
``process``, ``network`` and ``authentication`` dicts so the SentinelForge
normalizer can extract them correctly.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def _deterministic_rng(seed: int) -> random.Random:
    """Create a seeded RNG for reproducible synthetic dataset generation.

    Used exclusively for generating synthetic test datasets where seed
    reproducibility is required for deterministic test output. NOT used
    for any cryptographic or security-sensitive purpose.
    """
    return random.Random(seed)  # nosec B311


from sentinelforge.datasets.ground_truth import GroundTruthEntry, GroundTruthManifest
from sentinelforge.datasets.ground_truth_labels import (
    build_event_ground_truth,
)
from sentinelforge.datasets.scenarios import ScenarioLibrary

# Reserved test IP ranges (RFC 5737) and .example domains (RFC 2606)
TEST_IP_BLOCKS = ["192.0.2.", "198.51.100.", "203.0.113."]
EXAMPLE_DOMAINS = ["example.com", "example.org", "example.net"]

# Realistic host names (consistent across all event sources)
HOSTS = ["WKSTN-01", "WKSTN-02", "WKSTN-03", "SRV-01", "SRV-02", "DC-01", "LAPTOP-01"]

# Realistic usernames
USERS = ["jdoe", "asmith", "rjohnson", "mwilliams", "sadmin", "jdev", "opsuser"]

# Realistic process names
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

# Default start time for generated datasets
DEFAULT_START_TIME = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)

# Events per category (targets ~10,000+ total)
CATEGORY_COUNTS = {
    "windows_sysmon": 2000,
    "linux_auth": 2000,
    "firewall": 2000,
    "dns": 2000,
    "network": 2000,
    "correlated_attacks": 0,  # Populated by scenarios
    "benign_activity": 0,  # Populated by scenarios
}


def _iso(dt: datetime) -> str:
    """Format a datetime as ISO-8601 UTC."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_ip(rng: random.Random) -> str:
    """Return a reserved test IP address."""
    return f"{rng.choice(TEST_IP_BLOCKS)}{rng.randint(1, 254)}"


def _random_domain(rng: random.Random) -> str:
    """Return an example domain."""
    return rng.choice(EXAMPLE_DOMAINS)


def _random_host(rng: random.Random) -> str:
    return rng.choice(HOSTS)


def _random_user(rng: random.Random) -> str:
    return rng.choice(USERS)


def _random_process(rng: random.Random) -> str:
    return rng.choice(PROCESS_NAMES)


def _event_id(prefix: str, seq: int) -> str:
    return f"{prefix}-{seq:06d}"


def _base_event(
    event_id: str,
    timestamp: str,
    event_type: str,
    host: str,
    user: str,
    source: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a raw event dict with common fields at the top level."""
    ev: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "host": host,
        "user": user,
        "source": source,
    }
    if extra:
        ev.update(extra)
    return ev


class DatasetGenerator:
    """Generates a reproducible synthetic enterprise SOC dataset."""

    def __init__(
        self,
        seed: int = 42,
        start_time: datetime | None = None,
        output_dir: str | Path | None = None,
    ) -> None:
        self.seed = seed
        self.rng = _deterministic_rng(seed)
        self.start_time = start_time or DEFAULT_START_TIME
        self.output_dir = Path(output_dir or "data/generated")
        self.dataset_id = "sentinelforge-ds-001"
        self.manifest = GroundTruthManifest(dataset_id=self.dataset_id)
        self.events_by_category: dict[str, list[dict]] = {
            cat: [] for cat in CATEGORY_COUNTS
        }
        self.all_event_ids: set[str] = set()

    # ------------------------------------------------------------------
    # Category generators
    # ------------------------------------------------------------------

    def _generate_windows_sysmon(self, count: int) -> list[dict]:
        """Generate Windows Sysmon-style events with nested process/network."""
        events: list[dict] = []
        for i in range(count):
            ts = _iso(
                self.start_time + timedelta(seconds=self.rng.randint(0, 7 * 24 * 3600))
            )
            host = _random_host(self.rng)
            user = _random_user(self.rng)
            proc = _random_process(self.rng)
            event_type = self.rng.choice(
                [
                    "process.create",
                    "process.terminate",
                    "file.create",
                    "file.download",
                    "network.connect",
                    "file.open",
                ]
            )

            proc_info: dict[str, Any] = {
                "name": proc,
                "path": f"C:\\\\Windows\\\\System32\\\\{proc}",
                "pid": self.rng.randint(1000, 99999),
                "command_line": f"{proc} -legit-args",
                "user": user,
            }
            if proc in ("powershell.exe", "pwsh.exe"):
                # Mix of benign and suspicious PowerShell command lines.
                # Labels come from scenario intent, not detection output.
                ps_roll = self.rng.random()
                if ps_roll < 0.4:
                    # Suspicious: execution policy bypass (weight 6 indicator).
                    proc_info["command_line"] = (
                        f"{proc} -ExecutionPolicy Bypass -File "
                        f"C:\\\\Users\\\\{user}\\\\script.ps1"
                    )
                    proc_info["ppid"] = self.rng.randint(1000, 99999)
                elif ps_roll < 0.6:
                    # Benign-looking but legitimate: RemoteSigned policy (not Bypass).
                    proc_info["command_line"] = (
                        f"{proc} -ExecutionPolicy RemoteSigned -File "
                        f"C:\\\\Program Files\\\\Scripts\\\\AdminTool.ps1"
                    )
                elif ps_roll < 0.75:
                    # Benign: NoProfile with simple admin command.
                    proc_info["command_line"] = (
                        f"{proc} -NoProfile -Command Get-Service"
                    )
                elif ps_roll < 0.85:
                    # Benign: simple command, no suspicious indicators.
                    proc_info["command_line"] = f"{proc} -Command Get-Process"
                else:
                    # Benign: encoded command for legitimate obfuscation of
                    # non-malicious content (e.g., licensed software).
                    proc_info["command_line"] = (
                        f"{proc} -EncodedCommand "
                        f"UwBlbmQtTWlsZSBNZXNzYWdl"  # base64 of "Send-Message"
                    )

            net_info: dict[str, Any] | None = None
            if event_type == "network.connect":
                net_info = {
                    "direction": "outbound",
                    "remote_address": _random_ip(self.rng),
                    "remote_port": str(self.rng.choice([80, 443, 4433, 8080])),
                    "protocol": "tcp",
                }

            extra: dict[str, Any] = {"process": proc_info}
            if net_info:
                extra["network"] = net_info
            if event_type in ("file.create", "file.download", "file.open"):
                extra["file_name"] = (
                    f"C:\\\\Users\\\\{user}\\\\Documents\\\\file_{i}.txt"
                )

            events.append(
                _base_event(
                    event_id=_event_id("sysmon", i),
                    timestamp=ts,
                    event_type=event_type,
                    host=host,
                    user=user,
                    source="jsonl",
                    extra=extra,
                )
            )
        return events

    def _generate_linux_auth(self, count: int) -> list[dict]:
        """Generate Linux authentication events with nested authentication."""
        events: list[dict] = []
        for i in range(count):
            ts = _iso(
                self.start_time + timedelta(seconds=self.rng.randint(0, 7 * 24 * 3600))
            )
            host = _random_host(self.rng)
            user = _random_user(self.rng)
            source_ip = _random_ip(self.rng)
            outcome = self.rng.choice(
                ["success", "success", "success", "failure", "failure", "failure"]
            )
            events.append(
                _base_event(
                    event_id=_event_id("auth", i),
                    timestamp=ts,
                    event_type=f"auth.login.{outcome}",
                    host=host,
                    user=user,
                    source="linux_auth",
                    extra={
                        "authentication": {
                            "outcome": outcome,
                            "method": "ssh",
                            "username": user,
                            "source_address": source_ip,
                        }
                    },
                )
            )
        return events

    def _generate_firewall(self, count: int) -> list[dict]:
        """Generate firewall events with nested network."""
        events: list[dict] = []
        for i in range(count):
            ts = _iso(
                self.start_time + timedelta(seconds=self.rng.randint(0, 7 * 24 * 3600))
            )
            host = _random_host(self.rng)
            action = self.rng.choice(["allow", "allow", "allow", "deny"])
            direction = self.rng.choice(["inbound", "outbound"])
            src_ip = _random_ip(self.rng)
            dst_ip = _random_ip(self.rng)
            dst_port = self.rng.choice([80, 443, 4433, 8080, 22, 3389])
            events.append(
                _base_event(
                    event_id=_event_id("fw", i),
                    timestamp=ts,
                    event_type="firewall.connection",
                    host=host,
                    user="system",
                    source="firewall",
                    extra={
                        "network": {
                            "direction": direction,
                            "local_address": src_ip,
                            "remote_address": dst_ip,
                            "remote_port": str(dst_port),
                            "protocol": "tcp",
                        },
                        "action": action,
                    },
                )
            )
        return events

    def _generate_dns(self, count: int) -> list[dict]:
        """Generate DNS query events."""
        events: list[dict] = []
        for i in range(count):
            ts = _iso(
                self.start_time + timedelta(seconds=self.rng.randint(0, 7 * 24 * 3600))
            )
            host = _random_host(self.rng)
            domain = _random_domain(self.rng)
            if self.rng.random() < 0.05:
                domain = f"suspicious-{self.rng.randint(1000, 9999)}.example.com"
            events.append(
                _base_event(
                    event_id=_event_id("dns", i),
                    timestamp=ts,
                    event_type="dns.query",
                    host=host,
                    user="system",
                    source="dns",
                    extra={
                        "query": domain,
                        "query_type": "A",
                        "response_code": "NOERROR",
                        "source_address": _random_ip(self.rng),
                    },
                )
            )
        return events

    def _generate_network(self, count: int) -> list[dict]:
        """Generate network connection events with nested network/process."""
        events: list[dict] = []
        for i in range(count):
            ts = _iso(
                self.start_time + timedelta(seconds=self.rng.randint(0, 7 * 24 * 3600))
            )
            host = _random_host(self.rng)
            user = _random_user(self.rng)
            conn_type = self.rng.choice(
                [
                    "regular",
                    "regular",
                    "regular",
                    "jittered",
                    "irregular",
                    "heartbeat",
                    "update",
                ]
            )
            if conn_type == "heartbeat":
                dest = "169.254.169.254"
                port = "443"
                proc = "EDRAgent.exe"
            elif conn_type == "update":
                dest = _random_domain(self.rng)
                port = "443"
                proc = "svchost.exe"
            else:
                dest = _random_ip(self.rng)
                port = str(self.rng.choice([443, 4433, 8443, 8080]))
                proc = _random_process(self.rng)

            net_info: dict[str, Any] = {
                "direction": "outbound",
                "remote_address": dest,
                "remote_port": port,
                "protocol": "tcp",
            }
            proc_info: dict[str, Any] = {
                "name": proc,
                "pid": self.rng.randint(1000, 9999),
            }

            events.append(
                _base_event(
                    event_id=_event_id("net", i),
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user=user,
                    source="network",
                    extra={
                        "network": net_info,
                        "process": proc_info,
                    },
                )
            )
        return events

    # ------------------------------------------------------------------
    # Main generation
    # ------------------------------------------------------------------

    def generate(self, total_events: int = 10000) -> dict[str, Any]:
        """Generate the complete synthetic dataset.

        Returns a generation summary dict.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate each category
        per_category = total_events // (len(CATEGORY_COUNTS) - 2)
        remainder = total_events % (len(CATEGORY_COUNTS) - 2)

        cat_order = [
            c
            for c in CATEGORY_COUNTS
            if c not in ("correlated_attacks", "benign_activity")
        ]
        for idx, cat in enumerate(cat_order):
            n = per_category + (1 if idx < remainder else 0)
            if cat == "windows_sysmon":
                self.events_by_category[cat] = self._generate_windows_sysmon(n)
            elif cat == "linux_auth":
                self.events_by_category[cat] = self._generate_linux_auth(n)
            elif cat == "firewall":
                self.events_by_category[cat] = self._generate_firewall(n)
            elif cat == "dns":
                self.events_by_category[cat] = self._generate_dns(n)
            elif cat == "network":
                self.events_by_category[cat] = self._generate_network(n)

        # Generate correlated attack scenarios (adds extra events)
        scenario_events = self._generate_scenarios()
        self.events_by_category["correlated_attacks"] = scenario_events["attacks"]
        self.events_by_category["benign_activity"] = scenario_events["benign"]

        # Write category files
        for cat, events in self.events_by_category.items():
            if not events:
                continue
            filepath = self.output_dir / f"{cat}.jsonl"
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.writelines(
                    json.dumps(ev, ensure_ascii=False) + "\n" for ev in events
                )
            self.all_event_ids.update(ev["event_id"] for ev in events)

        # Write ground truth manifest (separate from raw events)
        gt_path = self.output_dir / "ground_truth.json"
        with open(gt_path, "w", encoding="utf-8") as fh:
            json.dump(self.manifest.to_dict(), fh, indent=2)

        # Build and write per-event ground truth labels (TASK 1).
        all_event_dicts: list[dict] = []
        for events in self.events_by_category.values():
            all_event_dicts.extend(events)

        scenario_entry_dicts = [
            {
                "scenario_id": e.scenario_id,
                "classification": e.classification,
                "event_ids": list(e.event_ids),
                "expected_detection_category": e.expected_detection_category,
                "expected_severity_range": e.expected_severity_range,
                "explanation": e.explanation,
            }
            for e in self.manifest.entries
        ]

        event_gt = build_event_ground_truth(
            dataset_id=self.dataset_id,
            all_events=all_event_dicts,
            scenario_entries=scenario_entry_dicts,
        )
        event_gt_path = self.output_dir / "event_ground_truth.json"
        event_gt.write_json(event_gt_path)

        # Write dataset manifest
        manifest = {
            "dataset_id": self.dataset_id,
            "seed": self.seed,
            "start_time": _iso(self.start_time),
            "total_events": sum(len(v) for v in self.events_by_category.values()),
            "events_by_category": {
                cat: len(evts) for cat, evts in self.events_by_category.items()
            },
            "ground_truth_entries": len(self.manifest.entries),
            "output_directory": str(self.output_dir),
        }
        manifest_path = self.output_dir / "dataset_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        return manifest

    def _generate_scenarios(self) -> dict[str, list[dict]]:
        """Generate correlated attack scenarios and benign activity.

        Ground-truth entries are added to the manifest; events are returned
        separately for attack and benign categories.
        """
        library = ScenarioLibrary()
        attack_events: list[dict] = []
        benign_events: list[dict] = []

        seq_offset = len(self.all_event_ids)
        current_time = self.start_time
        event_counter = 0

        for scenario in library.all():
            events, start_ts, end_ts = scenario.generate(
                seed=self.seed + seq_offset + event_counter,
                start_time=current_time,
                hosts=HOSTS,
                users=USERS,
            )
            # Re-assign event IDs to avoid collisions
            for ev in events:
                ev["event_id"] = _event_id(
                    f"scen-{scenario.scenario_id}",
                    event_counter,
                )
                event_counter += 1

            # Build ground-truth entry
            event_ids = tuple(ev["event_id"] for ev in events)
            self.manifest.add_entry(
                GroundTruthEntry(
                    dataset_id=self.dataset_id,
                    scenario_id=scenario.scenario_id,
                    event_ids=event_ids,
                    expected_behaviour=scenario.expected_behaviour,
                    classification=scenario.classification,
                    expected_detection_category=scenario.expected_detection_category,
                    expected_severity_range=scenario.expected_severity_range,
                    att_ck_candidate_mappings=scenario.att_ck_candidate_mappings,
                    scenario_start_timestamp=start_ts,
                    scenario_end_timestamp=end_ts,
                    explanation=scenario.explanation,
                )
            )

            if scenario.classification == "benign":
                benign_events.extend(events)
            else:
                attack_events.extend(events)

            # Advance time for next scenario
            current_time = current_time + timedelta(hours=2)

        return {"attacks": attack_events, "benign": benign_events}
