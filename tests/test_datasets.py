"""Tests for the synthetic SOC dataset generator."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentinelforge.datasets.generator import DatasetGenerator
from sentinelforge.datasets.scenarios import ScenarioLibrary
from sentinelforge.datasets.validators import validate_dataset
from tests.test_evaluation import make_detection_result, evaluate_with_gt, make_gt_entry


def test_generator_creates_minimum_events():
    """Generator produces at least 10,000 events by default."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        manifest = gen.generate(total_events=10000)
        assert manifest["total_events"] >= 10000


def test_generator_is_deterministic():
    """Same seed produces identical output."""
    with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
        gen1 = DatasetGenerator(seed=42, output_dir=tmpdir1)
        gen2 = DatasetGenerator(seed=42, output_dir=tmpdir2)
        m1 = gen1.generate(total_events=5000)
        m2 = gen2.generate(total_events=5000)
        assert m1["total_events"] == m2["total_events"]
        assert m1["events_by_category"] == m2["events_by_category"]


def test_generator_has_separate_ground_truth():
    """Ground truth is stored in a separate file, not in raw events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        # Ground truth file exists and is separate from raw event files.
        gt_path = os.path.join(tmpdir, "ground_truth.json")
        assert os.path.exists(gt_path)

        with open(gt_path, "r", encoding="utf-8") as fh:
            gt = json.load(fh)
        assert gt["dataset_id"] == "sentinelforge-ds-001"
        assert gt["entry_count"] > 0

        # No raw event contains ground-truth labels.
        for cat_file in os.listdir(tmpdir):
            if not cat_file.endswith(".jsonl"):
                continue
            with open(os.path.join(tmpdir, cat_file), "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        event = json.loads(line)
                        assert "classification" not in event
                        assert "ground_truth" not in event
                        assert "label" not in event


def test_generator_validates_cleanly():
    """Generated dataset passes all validation checks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)
        results = validate_dataset(tmpdir)
        assert results["valid"] is True
        assert results["errors"] == []
        for name, check in results["checks"].items():
            assert check["passed"], f"Check {name} failed: {check}"


def test_scenario_library_has_defaults():
    """Scenario library contains registered scenarios."""
    lib = ScenarioLibrary()
    scenarios = lib.all()
    assert len(scenarios) >= 6
    ids = {s.scenario_id for s in scenarios}
    assert "scenario-st-001" in ids  # Sysmon process tree
    assert "scenario-st-002" in ids  # Brute force
    assert "scenario-st-005" in ids  # EDR heartbeat (benign)


def test_scenario_generates_deterministic_events():
    """Same scenario with same seed produces same events."""
    from datetime import datetime, timezone

    from sentinelforge.datasets.scenarios import SmallBruteForceScenario as BruteForceScenario

    start = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    hosts = ["WKSTN-01", "SRV-01"]
    users = ["jdoe", "asmith"]

    s1 = BruteForceScenario(
        scenario_id="test-sc-001",
        dataset_id="test-ds",
        expected_behaviour="test",
        classification="suspicious",
        expected_detection_category="failed_login_burst",
        expected_severity_range="high",
    )
    s2 = BruteForceScenario(
        scenario_id="test-sc-001",
        dataset_id="test-ds",
        expected_behaviour="test",
        classification="suspicious",
        expected_detection_category="failed_login_burst",
        expected_severity_range="high",
    )

    events1, _, _ = s1.generate(seed=42, start_time=start, hosts=hosts, users=users)
    events2, _, _ = s2.generate(seed=42, start_time=start, hosts=hosts, users=users)

    assert len(events1) == len(events2)
    for e1, e2 in zip(events1, events2):
        assert e1["event_id"] == e2["event_id"]
        assert e1["timestamp"] == e2["timestamp"]


def test_event_ground_truth_complete_coverage():
    """Every generated event has a ground-truth entry (TASK 1)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        from sentinelforge.datasets.ground_truth_labels import (
            EventGroundTruthManifest,
        )
        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        assert os.path.exists(gt_path)

        manifest = EventGroundTruthManifest.load_json(gt_path)
        assert len(manifest.entries) >= 10000

        # Every event in the dataset should have a ground-truth entry.
        all_event_ids = set()
        for cat_file in os.listdir(tmpdir):
            if not cat_file.endswith(".jsonl"):
                continue
            with open(os.path.join(tmpdir, cat_file), "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        import json as _json
                        ev = _json.loads(line)
                        all_event_ids.add(ev["event_id"])

        gt_event_ids = set(manifest.entries.keys())
        assert gt_event_ids == all_event_ids, (
            f"Missing GT for {len(all_event_ids - gt_event_ids)} events, "
            f"extra GT for {len(gt_event_ids - all_event_ids)} events"
        )


def test_event_ground_truth_classifications():
    """Ground truth classifications are benign/suspicious/unlabeled only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=5000)

        from sentinelforge.datasets.ground_truth_labels import (
            EventGroundTruthManifest,
        )
        manifest = EventGroundTruthManifest.load_json(
            os.path.join(tmpdir, "event_ground_truth.json")
        )

        valid_classifications = {"benign", "suspicious", "unlabeled"}
        for entry in manifest.entries.values():
            assert entry.classification in valid_classifications, (
                f"Invalid classification {entry.classification} for {entry.event_id}"
            )


def test_event_ground_truth_no_unknown_as_benign():
    """Unknown events are 'unlabeled', never silently classified as benign."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        manifest = gen.generate(total_events=5000)

        from sentinelforge.datasets.ground_truth_labels import (
            EventGroundTruthManifest,
        )
        gt_manifest = EventGroundTruthManifest.load_json(
            os.path.join(tmpdir, "event_ground_truth.json")
        )

        counts = gt_manifest.counts()
        # Bulk events (not in scenarios) should be unlabeled, not benign.
        assert counts.get("unlabeled", 0) > 0, (
            "Expected some unlabeled events for bulk non-scenario data"
        )


def test_benign_powershell_admin_not_flagged():
    """Benign PowerShell admin commands don't trigger the PowerShell rule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=5000)

        from sentinelforge.detection.powershell import SuspiciousPowerShellRule
        from sentinelforge.detection.base import RuleRegistry
        from sentinelforge.ingestion.reader import reader_for
        from sentinelforge.ingestion.normalizer import normalize
        from pathlib import Path

        # Read benign activity events
        benign_path = Path(tmpdir) / "benign_activity.jsonl"
        assert benign_path.exists()

        reader = reader_for(benign_path)
        events = [normalize(raw, source="jsonl") for raw in reader.read(str(benign_path))]

        registry = RuleRegistry()
        registry.register(SuspiciousPowerShellRule())
        results = registry.evaluate_all(events)

        # Benign PowerShell admin commands should not produce alerts.
        # Note: The BenignPowerShellVariantsScenario includes a benign encoded
        # command (-EncodedCommand) which matches the encoded_command indicator
        # pattern. The detection rule cannot distinguish benign from malicious
        # encoded commands, so this produces 1 FP. All other benign commands
        # (Get-Process, Get-Service, RemoteSigned, NoProfile) produce no alerts.
        powershell_alerts = [
            r for r in results
            if r.rule_id == "sentinelforge.detection.suspicious_powershell"
        ]
        # 1 alert from the benign encoded command (legitimate FP - detection
        # rule cannot distinguish benign from malicious encoded commands)
        assert len(powershell_alerts) == 1, (
            f"Expected 1 FP from benign encoded command, got {len(powershell_alerts)}"
        )
        # The alert should be on the encoded command event
        assert powershell_alerts[0].metadata["indicators"] == ["encoded_command"]


def test_sysmon_reader_parses_generic_jsonl():
    """The windows_sysmon.jsonl file uses generic JSONL format (not native EVTX)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        from sentinelforge.ingestion.reader import reader_for
        from pathlib import Path

        sysmon_path = Path(tmpdir) / "windows_sysmon.jsonl"
        assert sysmon_path.exists()

        reader = reader_for(sysmon_path)
        events = list(reader.read(str(sysmon_path)))
        assert len(events) == 2000

        # Generic JSONL records have top-level event_id, timestamp, event_type
        for ev in events[:5]:
            assert "event_id" in ev
            assert "timestamp" in ev
            assert "event_type" in ev

        # They do NOT have native Sysmon EVTX structure (Event/System/EventData)
        assert "Event" not in events[0], (
            "windows_sysmon.jsonl should be generic JSONL, not native Sysmon EVTX"
        )


def test_password_spray_scenario_detected():
    """The password spraying scenario is detected by PasswordSprayRule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        from sentinelforge.detection.password_spray import PasswordSprayRule
        from sentinelforge.detection.base import RuleRegistry
        from sentinelforge.ingestion.reader import reader_for
        from sentinelforge.ingestion.normalizer import normalize
        from pathlib import Path

        # Password spraying scenario events are in correlated_attacks.jsonl
        attacks_path = Path(tmpdir) / "correlated_attacks.jsonl"
        assert attacks_path.exists()

        reader = reader_for(attacks_path)
        events = [normalize(raw, source="jsonl") for raw in reader.read(str(attacks_path))]

        registry = RuleRegistry()
        registry.register(PasswordSprayRule())
        results = registry.evaluate_all(events)

        # The dataset includes a password spraying scenario (scenario-st-003)
        # with 6 failed logins from one source against 6 different users.
        spray_alerts = [
            r for r in results
            if r.rule_id == "sentinelforge.detection.password_spray"
        ]
        assert len(spray_alerts) >= 1, (
            "Password spraying scenario should be detected"
        )


def test_native_sysmon_generation():
    """Native Sysmon generator produces valid EVTX-converted JSON events."""
    from sentinelforge.datasets.native_sysmon import (
        generate_native_sysmon_events,
    )

    events = generate_native_sysmon_events(count=100, seed=42)
    assert len(events) == 100

    # Every event must have native Sysmon structure
    for ev in events:
        assert "Event" in ev
        assert "System" in ev["Event"]
        assert "EventData" in ev["Event"]
        assert "EventID" in ev["Event"]["System"]
        assert "TimeCreated" in ev["Event"]["System"]
        assert "Computer" in ev["Event"]["System"]
        assert "Data" in ev["Event"]["EventData"]

    # Event IDs should be 1, 3, 11, or 22
    event_ids = {ev["Event"]["System"]["EventID"] for ev in events}
    assert event_ids == {1, 3, 11, 22}


def test_native_sysmon_jsonl_roundtrip():
    """Native Sysmon JSONL can be written and read back."""
    import tempfile
    import os

    from sentinelforge.datasets.native_sysmon import (
        generate_native_sysmon_events,
        write_native_sysmon_jsonl,
    )

    events = generate_native_sysmon_events(count=50, seed=42)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "native_sysmon.jsonl")
        write_native_sysmon_jsonl(events, path)
        assert os.path.exists(path)

        # Read back and verify
        with open(path, "r", encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]
        assert len(lines) == 50

        import json as _json
        for line in lines:
            ev = _json.loads(line)
            assert "Event" in ev
            assert "System" in ev["Event"]


def test_sysmon_reader_parses_native_sysmon():
    """SysmonReader correctly parses native Sysmon EVTX-converted JSON."""
    import tempfile
    import os

    from sentinelforge.datasets.native_sysmon import (
        generate_native_sysmon_events,
        write_native_sysmon_jsonl,
    )
    from sentinelforge.ingestion.reader import reader_for

    events = generate_native_sysmon_events(count=50, seed=42)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Use .evt extension so content sniffing selects SysmonReader
        # (reader_for returns JSONLReader for .jsonl files)
        path = os.path.join(tmpdir, "native_sysmon.evt")
        write_native_sysmon_jsonl(events, path)

        from sentinelforge.ingestion.reader import SysmonReader
        reader = reader_for(path)
        assert isinstance(reader, SysmonReader), (
            f"Expected SysmonReader, got {type(reader).__name__}"
        )

        parsed = list(reader.read(path))
        assert len(parsed) == 50

        # Each parsed record should have Event/System/EventData
        for ev in parsed:
            assert "Event" in ev
            assert "System" in ev["Event"]
            assert "EventData" in ev["Event"]


def test_sysmon_reader_normalizes_native_events():
    """Native Sysmon events normalize correctly through the normalizer."""
    import tempfile
    import os

    from sentinelforge.datasets.native_sysmon import (
        generate_native_sysmon_events,
        write_native_sysmon_jsonl,
    )
    from sentinelforge.ingestion.reader import reader_for
    from sentinelforge.ingestion.normalizer import normalize

    events = generate_native_sysmon_events(count=20, seed=42)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "native_sysmon.jsonl")
        write_native_sysmon_jsonl(events, path)

        reader = reader_for(path)
        raw_events = list(reader.read(path))

        for raw in raw_events:
            nev = normalize(raw, source="sysmon")
            assert nev.event_id is not None
            assert nev.timestamp is not None
            assert nev.source == "sysmon"
            assert nev.raw == raw  # raw preserved verbatim
            # Sysmon events should have process info extracted
            assert nev.process is not None
            assert nev.process.name is not None
            assert nev.process.pid is not None


# ---------------------------------------------------------------------------
# Reader selection tests (M8.3.1 corrections)
# ---------------------------------------------------------------------------

def test_reader_for_jsonl_sysmon_content():
    """.jsonl with Sysmon-formatted content selects SysmonReader."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, SysmonReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sysmon.jsonl")
        with open(p, "w") as f:
            f.write('{"Event": {"System": {"EventID": 1}, "EventData": {"Data": []}}}\n')
        reader = reader_for(p)
        assert isinstance(reader, SysmonReader), f"Expected SysmonReader, got {type(reader).__name__}"


def test_reader_for_jsonl_generic_content():
    """.jsonl with generic content selects JSONLReader."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, JSONLReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "generic.jsonl")
        with open(p, "w") as f:
            f.write('{"event_id": "1", "event_type": "auth"}\n')
        reader = reader_for(p)
        assert isinstance(reader, JSONLReader), f"Expected JSONLReader, got {type(reader).__name__}"


def test_reader_for_long_first_line_over_200_chars():
    """First JSONL record longer than 200 chars is read in full."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, SysmonReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "long.jsonl")
        long_line = (
            '{"Event": {"System": {"EventID": 1, '
            '"Provider": {"Name": "Microsoft-Windows-Sysmon", '
            '"Guid": "{57709853-2263-4531-95CE-168E4D7F34C2}"}, '
            '"TimeCreated": {"SystemTime": "2024-01-15T08:00:00Z"}, '
            '"Computer": "HOST-01"}, '
            '"EventData": {"Data": [{"Name": "Image", "#text": "C:\\\\Windows\\\\System32\\\\powershell.exe"}, '
            '{"Name": "CommandLine", "#text": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand UwBlbmQtV2ViUmVxdWVzdA=="}]}}}'
        )
        with open(p, "w") as f:
            f.write(long_line + "\n")
        reader = reader_for(p)
        assert isinstance(reader, SysmonReader), f"Expected SysmonReader, got {type(reader).__name__}"


def test_reader_for_leading_blank_lines():
    """Leading blank lines do not break reader detection."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, SysmonReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blank.jsonl")
        with open(p, "w") as f:
            f.write("\n\n\n")
            f.write('{"Event": {"System": {"EventID": 1}, "EventData": {"Data": []}}}\n')
        reader = reader_for(p)
        assert isinstance(reader, SysmonReader), f"Expected SysmonReader, got {type(reader).__name__}"


def test_reader_for_json_sysmon_document():
    """.json with a single Sysmon document selects SysmonReader."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, SysmonReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sysmon.json")
        with open(p, "w") as f:
            f.write('{"Event": {"System": {"EventID": 1}, "EventData": {"Data": []}}}')
        reader = reader_for(p)
        assert isinstance(reader, SysmonReader), f"Expected SysmonReader, got {type(reader).__name__}"


def test_reader_for_json_generic_document():
    """.json with generic content selects JSONReader."""
    import tempfile, os
    from sentinelforge.ingestion.reader import reader_for, JSONReader
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "generic.json")
        with open(p, "w") as f:
            f.write('{"event_id": "1", "event_type": "auth"}')
        reader = reader_for(p)
        assert isinstance(reader, JSONReader), f"Expected JSONReader, got {type(reader).__name__}"


def test_jsonl_reader_raises_on_malformed_line():
    """JSONLReader raises LogParseError with line number on malformed line."""
    import tempfile, os
    from sentinelforge.ingestion.reader import JSONLReader, LogParseError
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.jsonl")
        with open(p, "w") as f:
            f.write('{"valid": 1}\n')
            f.write('{bad json\n')
            f.write('{"valid": 2}\n')
        reader = JSONLReader()
        try:
            list(reader.read(p))
            assert False, "Expected LogParseError"
        except LogParseError as e:
            assert e.line_number == 2, f"Expected line 2, got {e.line_number}"
            assert "bad json" in e.line


def test_sysmon_reader_raises_on_malformed_jsonl():
    """SysmonReader raises LogParseError on malformed JSONL lines."""
    import tempfile, os
    from sentinelforge.ingestion.reader import SysmonReader, LogParseError
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.evt")
        with open(p, "w") as f:
            f.write('{"Event": {"System": {"EventID": 1}, "EventData": {"Data": []}}}\n')
            f.write('{broken\n')
        reader = SysmonReader()
        try:
            list(reader.read(p))
            assert False, "Expected LogParseError"
        except LogParseError as e:
            assert e.line_number == 2, f"Expected line 2, got {e.line_number}"


# ---------------------------------------------------------------------------
# Sysmon Event ID independent tests (M8.3.1 corrections)
# ---------------------------------------------------------------------------

def _make_sysmon_event(event_id: int, timestamp: str, computer: str, data_fields: list[dict]) -> dict:
    """Build a Sysmon-style event dict."""
    data = [{"Name": k, "#text": v} for k, v in data_fields]
    return {
        "Event": {
            "System": {
                "Provider": {"Name": "Microsoft-Windows-Sysmon"},
                "EventID": event_id,
                "TimeCreated": {"SystemTime": timestamp},
                "Computer": computer,
            },
            "EventData": {"Data": data},
        }
    }


def test_sysmon_event_id_1_process_create():
    """Event ID 1 (Process Create): extract Event ID, timestamp, computer, process fields."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader

    event = _make_sysmon_event(
        event_id=1,
        timestamp="2024-01-15T08:00:00Z",
        computer="HOST-01",
        data_fields=[
            ("Image", "C:\\\\Windows\\\\System32\\\\powershell.exe"),
            ("CommandLine", "powershell.exe -ExecutionPolicy Bypass"),
            ("User", "DOMAIN\\\\user"),
            ("ProcessId", "1234"),
            ("ParentProcessId", "5678"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        records = list(reader.read(p))
        assert len(records) == 1
        rec = records[0]
        # Event ID extraction
        assert rec["Event"]["System"]["EventID"] == 1
        # Timestamp extraction
        assert rec["Event"]["System"]["TimeCreated"]["SystemTime"] == "2024-01-15T08:00:00Z"
        # Computer extraction
        assert rec["Event"]["System"]["Computer"] == "HOST-01"
        # EventData field extraction
        names = {d["Name"]: d["#text"] for d in rec["Event"]["EventData"]["Data"]}
        assert names["Image"] == "C:\\\\Windows\\\\System32\\\\powershell.exe"
        assert names["CommandLine"] == "powershell.exe -ExecutionPolicy Bypass"
        assert names["User"] == "DOMAIN\\\\user"
        assert names["ProcessId"] == "1234"
        assert names["ParentProcessId"] == "5678"
        # Raw event preservation
        assert "Event" in rec
        assert "System" in rec["Event"]


def test_sysmon_event_id_3_network_connection():
    """Event ID 3 (Network Connection): extract Event ID, timestamp, computer, network fields."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader

    event = _make_sysmon_event(
        event_id=3,
        timestamp="2024-01-15T08:01:00Z",
        computer="HOST-01",
        data_fields=[
            ("SourceIp", "10.0.0.5"),
            ("DestinationIp", "198.51.100.42"),
            ("DestinationPort", "4433"),
            ("Protocol", "tcp"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        records = list(reader.read(p))
        assert len(records) == 1
        rec = records[0]
        assert rec["Event"]["System"]["EventID"] == 3
        assert rec["Event"]["System"]["TimeCreated"]["SystemTime"] == "2024-01-15T08:01:00Z"
        assert rec["Event"]["System"]["Computer"] == "HOST-01"
        names = {d["Name"]: d["#text"] for d in rec["Event"]["EventData"]["Data"]}
        assert names["DestinationIp"] == "198.51.100.42"
        assert names["DestinationPort"] == "4433"
        assert names["Protocol"] == "tcp"


def test_sysmon_event_id_11_file_create():
    """Event ID 11 (File Create): extract Event ID, timestamp, computer, file fields."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader

    event = _make_sysmon_event(
        event_id=11,
        timestamp="2024-01-15T08:02:00Z",
        computer="HOST-01",
        data_fields=[
            ("TargetFilename", "C:\\\\Users\\\\user\\\\Downloads\\\\payload.ps1"),
            ("CreationUtcTime", "2024-01-15T08:02:00Z"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        records = list(reader.read(p))
        assert len(records) == 1
        rec = records[0]
        assert rec["Event"]["System"]["EventID"] == 11
        assert rec["Event"]["System"]["TimeCreated"]["SystemTime"] == "2024-01-15T08:02:00Z"
        assert rec["Event"]["System"]["Computer"] == "HOST-01"
        names = {d["Name"]: d["#text"] for d in rec["Event"]["EventData"]["Data"]}
        assert names["TargetFilename"] == "C:\\\\Users\\\\user\\\\Downloads\\\\payload.ps1"


def test_sysmon_event_id_22_dns_query():
    """Event ID 22 (DNS Query): extract Event ID, timestamp, computer, DNS fields."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader

    event = _make_sysmon_event(
        event_id=22,
        timestamp="2024-01-15T08:03:00Z",
        computer="HOST-01",
        data_fields=[
            ("QueryName", "evil.example.com"),
            ("QueryType", "A"),
            ("QueryResults", "198.51.100.42"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        records = list(reader.read(p))
        assert len(records) == 1
        rec = records[0]
        assert rec["Event"]["System"]["EventID"] == 22
        assert rec["Event"]["System"]["TimeCreated"]["SystemTime"] == "2024-01-15T08:03:00Z"
        assert rec["Event"]["System"]["Computer"] == "HOST-01"
        names = {d["Name"]: d["#text"] for d in rec["Event"]["EventData"]["Data"]}
        assert names["QueryName"] == "evil.example.com"
        assert names["QueryType"] == "A"
        assert names["QueryResults"] == "198.51.100.42"


# ---------------------------------------------------------------------------
# Evaluation integrity tests (M8.3.1 corrections)
# ---------------------------------------------------------------------------

def test_attribution_error_not_counted_as_fp():
    """Category mismatch on suspicious evidence = attribution error, not FP."""
    gt_suspicious = [{
        "event_id": "evt-susp-1",
        "scenario_id": "scenario-st-002",
        "expected_detection_category": "failed_login_burst",
        "expected_severity_range": "high",
        "explanation": "Brute force",
    }]
    det = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    assert result.alert_level.false_positive_alerts == 0
    assert result.alert_level.attribution_error_alerts == 1
    assert result.alert_level.assessed_alerts == 1
    assert result.alert_level.precision == 0.0


def test_duplicate_detections_not_inflated_event_level():
    """Multiple detections of same event count once at event level."""
    gt_suspicious = [{
        "event_id": "evt-susp-1",
        "scenario_id": "scenario-st-001",
        "expected_detection_category": "suspicious_processtree",
        "expected_severity_range": "high",
        "explanation": "Word->PowerShell",
    }]
    det1 = make_detection_result(
        rule_id="sentinelforge.detection.suspicious_processtree",
        rule_name="Suspicious Process Tree",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1204.002",
    )
    det2 = make_detection_result(
        rule_id="sentinelforge.detection.suspicious_processtree",
        rule_name="Suspicious Process Tree (2nd)",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1204.002",
    )
    result = evaluate_with_gt([det1, det2], gt_suspicious, [])
    assert result.event_level.detected_suspicious_events == 1  # deduplicated
    assert result.alert_level.true_positive_alerts == 2  # both alerts count


def test_wrong_rule_on_suspicious_not_benign():
    """Suspicious event detected by wrong rule is not treated as benign."""
    gt_suspicious = [{
        "event_id": "evt-susp-1",
        "scenario_id": "scenario-st-007",
        "expected_detection_category": "failed_login_burst",
        "expected_severity_range": "high",
        "explanation": "Distributed brute force",
    }]
    # password_spray alert on a failed_login_burst event
    det = make_detection_result(
        rule_id="sentinelforge.detection.password_spray",
        rule_name="Password Spray",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110.003",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    # Event is still counted as suspicious (ground truth independent)
    assert result.event_level.total_suspicious_events == 1
    # Alert is attribution error, not FP
    assert result.alert_level.attribution_error_alerts == 1
    assert result.alert_level.false_positive_alerts == 0


def test_assessment_coverage_reported():
    """Assessment coverage = assessed / total is reported."""
    gt_suspicious = [{
        "event_id": "evt-susp-1",
        "scenario_id": "scenario-st-001",
        "expected_detection_category": "failed_login_burst",
        "expected_severity_range": "high",
        "explanation": "Brute force",
    }]
    gt_unlabeled = [{
        "event_id": "evt-unlabeled-1",
        "scenario_id": None,
        "expected_detection_category": "",
        "expected_severity_range": "",
        "explanation": "Not in scenario",
    }]
    det_tp = make_detection_result(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110",
    )
    det_unassessed = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-unlabeled-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det_tp, det_unassessed], gt_suspicious, [], gt_unlabeled)
    assert result.alert_level.total_alerts == 2
    assert result.alert_level.assessed_alerts == 1
    assert result.alert_level.unassessed_alerts == 1
    assert result.alert_level.assessment_coverage == 0.5  # 1 / 2


def test_aggregate_metrics_reconcile_with_per_rule():
    """System-level metrics equal the sum of per-rule metrics."""
    gt_suspicious = [
        {"event_id": "evt-1", "scenario_id": "s1", "expected_detection_category": "failed_login_burst", "expected_severity_range": "high", "explanation": "bf"},
        {"event_id": "evt-2", "scenario_id": "s2", "expected_detection_category": "c2_beacon", "expected_severity_range": "medium", "explanation": "beacon"},
    ]
    gt_benign = [
        {"event_id": "evt-b", "scenario_id": "s3", "expected_detection_category": "none", "expected_severity_range": "info", "explanation": "heartbeat"},
    ]
    det1 = make_detection_result("sentinelforge.detection.failed_login_burst", "Failed Login Burst", ["evt-1"], "T1110")
    det2 = make_detection_result("sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-2"], "T1071")
    det3 = make_detection_result("sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-b"], "T1071")  # FP on benign
    result = evaluate_with_gt([det1, det2, det3], gt_suspicious, gt_benign)

    # Aggregate
    assert result.alert_level.true_positive_alerts == 2
    assert result.alert_level.false_positive_alerts == 1
    assert result.alert_level.precision == round(2 / 3, 4)

    # Per-rule sum
    rule_tp = sum(m.true_positive_alerts for m in result.rule_alert_metrics)
    rule_fp = sum(m.false_positive_alerts for m in result.rule_alert_metrics)
    rule_total = sum(m.total_alerts for m in result.rule_alert_metrics)
    assert rule_tp == result.alert_level.true_positive_alerts
    assert rule_fp == result.alert_level.false_positive_alerts
    assert rule_total == result.alert_level.total_alerts


# ---------------------------------------------------------------------------
# Ground truth correction regression tests (M8.3.3)
# ---------------------------------------------------------------------------

def test_st015_brute_force_not_password_spray():
    """The 200 brute-force events in st-015-bf are not password spraying."""
    import tempfile, os
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        bf_events = [
            e for e in gt["entries"]
            if e["scenario_id"] == "scenario-st-015-bf"
        ]
        assert len(bf_events) == 200, f"Expected 200 brute-force events, got {len(bf_events)}"
        for e in bf_events:
            assert e["classification"] == "suspicious", f"{e['event_id']}: wrong classification"
            assert e["expected_detection_categories"] == ["failed_login_burst"], (
                f"{e['event_id']}: expected [failed_login_burst], got {e['expected_detection_categories']}"
            )


def test_st015_password_spray_classified_correctly():
    """The 204 password-spray events in st-015-ps are classified correctly."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        ps_events = [
            e for e in gt["entries"]
            if e["scenario_id"] == "scenario-st-015-ps"
        ]
        assert len(ps_events) == 204, f"Expected 204 password-spray events, got {len(ps_events)}"
        for e in ps_events:
            assert e["classification"] == "suspicious", f"{e['event_id']}: wrong classification"
            assert e["expected_detection_categories"] == ["password_spray"], (
                f"{e['event_id']}: expected [password_spray], got {e['expected_detection_categories']}"
            )


def test_st015_c2_beacon_not_password_spray():
    """The 200 C2 beacon events in st-015-c2 are not password spraying."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        c2_events = [
            e for e in gt["entries"]
            if e["scenario_id"] == "scenario-st-015-c2"
        ]
        assert len(c2_events) == 200, f"Expected 200 C2 beacon events, got {len(c2_events)}"
        for e in c2_events:
            assert e["classification"] == "suspicious", f"{e['event_id']}: wrong classification"
            assert e["expected_detection_categories"] == ["c2_beacon"], (
                f"{e['event_id']}: expected [c2_beacon], got {e['expected_detection_categories']}"
            )


def test_st003_password_spray_events():
    """The st-003 password-spray events remain correctly labelled."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        st003_events = [
            e for e in gt["entries"]
            if e["scenario_id"] == "scenario-st-003"
        ]
        assert len(st003_events) == 6, f"Expected 6 st-003 events, got {len(st003_events)}"
        for e in st003_events:
            assert e["classification"] == "suspicious", f"{e['event_id']}: wrong classification"
            assert e["expected_detection_categories"] == ["password_spray"], (
                f"{e['event_id']}: expected [password_spray], got {e['expected_detection_categories']}"
            )


def test_no_category_contamination_across_st015():
    """No st-015 event has multiple expected detection categories."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        st015_scenarios = ["scenario-st-015-bf", "scenario-st-015-ps", "scenario-st-015-c2"]
        for e in gt["entries"]:
            if e["scenario_id"] in st015_scenarios:
                cats = e["expected_detection_categories"]
                assert len(cats) == 1, (
                    f"{e['event_id']}: expected exactly 1 category, got {cats}"
                )


def test_ground_truth_counts_reconcile_with_generator():
    """Ground-truth counts reconcile with scenario generator output."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        manifest = gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # Count by category across all entries
        category_counts = Counter()
        for e in gt["entries"]:
            for cat in e.get("expected_detection_categories", []):
                category_counts[cat] += 1

        # Verify st-015-specific counts
        bf_count = sum(1 for e in gt["entries"] if e["scenario_id"] == "scenario-st-015-bf")
        ps_count = sum(1 for e in gt["entries"] if e["scenario_id"] == "scenario-st-015-ps")
        c2_count = sum(1 for e in gt["entries"] if e["scenario_id"] == "scenario-st-015-c2")
        assert bf_count == 200
        assert ps_count == 204
        assert c2_count == 200

        # Total suspicious = sum of all scenario suspicious events
        suspicious_count = sum(1 for e in gt["entries"] if e["classification"] == "suspicious")
        assert suspicious_count == 641, f"Expected 641 suspicious, got {suspicious_count}"

        # Total labeled = suspicious + benign
        labeled_count = sum(1 for e in gt["entries"] if e["classification"] in ("suspicious", "benign"))
        assert labeled_count == 1298, f"Expected 1298 labeled, got {labeled_count}"

        # st-002: 8 failed_login_burst events + 1 successful login (contextual,
        # no category). Total suspicious events from st-002 = 9.
        st002_events = [e for e in gt["entries"] if e["scenario_id"] == "scenario-st-002"]
        assert len(st002_events) == 9, f"Expected 9 st-002 events, got {len(st002_events)}"
        st002_bf_events = [e for e in st002_events if "failed_login_burst" in e.get("expected_detection_categories", [])]
        assert len(st002_bf_events) == 8, f"Expected 8 failed_login_burst events in st-002, got {len(st002_bf_events)}"
        st002_success_events = [e for e in st002_events if e.get("event_type") == "auth.login.success"]
        assert len(st002_success_events) == 1, f"Expected 1 successful login in st-002, got {len(st002_success_events)}"
        assert not st002_success_events[0].get("expected_detection_categories"), (
            "Successful login should have no detection category (contextual evidence)"
        )


def test_detection_output_cannot_affect_ground_truth():
    """Ground truth is assigned before detection runs - detection output cannot affect labels."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=11879)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # All st-015-c2 events are c2_beacon, regardless of what PowerShell rule detects
        c2_events = [
            e for e in gt["entries"]
            if e["scenario_id"] == "scenario-st-015-c2"
        ]
        for e in c2_events:
            assert "password_spray" not in e["expected_detection_categories"], (
                f"{e['event_id']}: C2 beacon event incorrectly tagged as password_spray"
            )
            assert "failed_login_burst" not in e["expected_detection_categories"], (
                f"{e['event_id']}: C2 beacon event incorrectly tagged as failed_login_burst"
            )


def test_duplicate_detections_do_not_inflate_event_recall():
    """Multiple detections of the same event count once at event level."""
    from sentinelforge.datasets.evaluation import evaluate_detections
    from tests.test_evaluation import make_detection_result, make_gt_entry, evaluate_with_gt

    gt_entry = make_gt_entry(
        "evt-susp-1", "suspicious", "scenario-st-001",
        "suspicious_processtree", "high", "Word->PowerShell",
    )
    det1 = make_detection_result(
        rule_id="sentinelforge.detection.suspicious_processtree",
        rule_name="Suspicious Process Tree",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1204.002",
    )
    det2 = make_detection_result(
        rule_id="sentinelforge.detection.suspicious_processtree",
        rule_name="Suspicious Process Tree (2nd)",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1204.002",
    )
    det3 = make_detection_result(
        rule_id="sentinelforge.detection.suspicious_processtree",
        rule_name="Suspicious Process Tree (3rd)",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1204.002",
    )

    result = evaluate_with_gt([det1, det2, det3], [gt_entry], [])

    # Event level: 1 event detected once (deduplicated)
    assert result.event_level.detected_suspicious_events == 1
    assert result.event_level.undetected_suspicious_events == 0
    assert result.event_level.recall == 1.0

    # Alert level: 3 alerts, all TP
    assert result.alert_level.true_positive_alerts == 3


# ---------------------------------------------------------------------------
# Ground-truth independence regression tests (M8.3.4 TASK 5)
# ---------------------------------------------------------------------------

def test_ground_truth_derives_from_scenario_intent():
    """Ground-truth labels come from scenario generation, not detection output."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=11879)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # Every labeled event's category matches its scenario's expected category
        scenario_categories = {
            "scenario-st-015-bf": {"failed_login_burst"},
            "scenario-st-015-ps": {"password_spray"},
            "scenario-st-015-c2": {"c2_beacon"},
            "scenario-st-002": {"failed_login_burst"},
            "scenario-st-003": {"password_spray"},
            "scenario-st-004": {"c2_beacon"},
        }
        for e in gt["entries"]:
            sid = e.get("scenario_id")
            if sid in scenario_categories:
                expected = scenario_categories[sid]
                actual = set(e.get("expected_detection_categories", []))
                # st-002's successful login (evt-009) is contextual evidence,
                # not a detection-bearing failed_login_burst event
                if sid == "scenario-st-002" and e.get("event_type") == "auth.login.success":
                    expected = set()
                assert actual == expected, (
                    f"{e['event_id']}: scenario {sid} expects {expected}, got {actual}"
                )


def test_raw_logs_contain_no_ground_truth_labels():
    """Raw event files do not contain embedded ground-truth labels."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=11879)

        # Check all raw event files for embedded labels
        raw_files = [
            "windows_sysmon.jsonl", "linux_auth.jsonl", "firewall.jsonl",
            "dns.jsonl", "network.jsonl", "correlated_attacks.jsonl",
            "benign_activity.jsonl",
        ]
        for fname in raw_files:
            fpath = os.path.join(tmpdir, fname)
            with open(fpath) as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = json.loads(line)
                    # Raw events must not contain classification, scenario_id, or
                    # expected_detection_categories fields
                    for forbidden in ("classification", "scenario_id",
                                       "expected_detection_category",
                                       "expected_detection_categories",
                                       "expected_severity", "explanation"):
                        assert forbidden not in event, (
                            f"{fname}:{line_num}: raw event contains forbidden field '{forbidden}': {event.get('event_id')}"
                        )


def test_every_labeled_event_has_valid_scenario():
    """Every labeled event has a valid scenario association."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=11879)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # Build set of valid scenario IDs from ground_truth.json
        gt_manifest_path = os.path.join(tmpdir, "ground_truth.json")
        with open(gt_manifest_path) as fh:
            manifest = json.load(fh)
        valid_scenarios = {e["scenario_id"] for e in manifest["entries"]}

        for e in gt["entries"]:
            if e["classification"] in ("suspicious", "benign"):
                sid = e.get("scenario_id")
                assert sid is not None, f"{e['event_id']}: labeled but no scenario_id"
                assert sid in valid_scenarios, (
                    f"{e['event_id']}: scenario_id {sid} not in ground truth manifest"
                )


def test_no_contradictory_category_assignments():
    """No event has contradictory or overlapping category assignments."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=11879)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # No event should have both benign and suspicious indicators
        for e in gt["entries"]:
            cats = e.get("expected_detection_categories", [])
            classification = e["classification"]
            if classification == "benign":
                # Benign events should not have attack categories
                attack_cats = {"failed_login_burst", "password_spray", "c2_beacon",
                               "suspicious_processtree", "t1059.001", "t1204.002"}
                assert not (set(cats) & attack_cats), (
                    f"{e['event_id']}: benign event has attack categories {cats}"
                )
            elif classification == "suspicious":
                # Suspicious events should have at least one attack category,
                # UNLESS they're contextual/corroborating evidence (e.g., a
                # successful login in a brute-force scenario).
                if not cats and e.get("event_type") != "auth.login.success":
                    assert cats, (
                        f"{e['event_id']}: suspicious event with no categories "
                        "and is not contextual evidence"
                    )


def test_detection_results_cannot_alter_ground_truth():
    """Ground truth is immutable - detection results don't change labels."""
    from sentinelforge.datasets.evaluation import evaluate_detections
    from tests.test_evaluation import make_detection_result, make_gt_entry

    gt_entry = make_gt_entry(
        "evt-susp-1", "suspicious", "scenario-st-003",
        "password_spray", "high", "Password spraying",
    )
    # Even if no detection matches, ground truth stays the same
    result_no_det = evaluate_detections(
        "test-ds", [],
        {"dataset_id": "test-ds", "total_events": 1,
         "entries": [make_gt_entry(**gt_entry.to_dict() if hasattr(gt_entry, 'to_dict') else gt_entry)]},
    )
    # Ground truth counts should be unchanged regardless of detections
    assert result_no_det.event_level.total_suspicious_events == 1
    assert result_no_det.suspicious_events == 1

    # Even with many detections on the same event, ground truth doesn't change
    det = make_detection_result(
        rule_id="sentinelforge.detection.password_spray",
        rule_name="Password Spray",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110.003",
    )
    result_many_det = evaluate_detections(
        "test-ds", [det] * 100,
        {"dataset_id": "test-ds", "total_events": 1,
         "entries": [make_gt_entry(**gt_entry.to_dict() if hasattr(gt_entry, 'to_dict') else gt_entry)]},
    )
    assert result_many_det.event_level.total_suspicious_events == 1
    assert result_many_det.suspicious_events == 1


def test_all_registered_scenarios_match_ground_truth():
    """Every event's category matches its scenario's declared metadata."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator
    from sentinelforge.datasets.scenarios import ScenarioLibrary

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        # Build scenario -> expected category mapping from ScenarioLibrary
        lib = ScenarioLibrary()
        scenario_categories = {
            s.scenario_id: set(
                c.strip().lower()
                for c in s.expected_detection_category.split(",")
                if c.strip()
            )
            for s in lib.all()
        }

        for e in gt["entries"]:
            sid = e.get("scenario_id")
            if sid and sid in scenario_categories:
                expected = scenario_categories[sid]
                actual = set(e.get("expected_detection_categories", []))
                # st-002's successful login (evt-009) is contextual evidence,
                # not a detection-bearing failed_login_burst event
                if sid == "scenario-st-002" and e.get("event_type") == "auth.login.success":
                    expected = set()
                assert actual == expected, (
                    f"{e['event_id']}: scenario {sid} expects {expected}, got {actual}"
                )


def test_no_duplicate_event_ids():
    """No duplicate event IDs exist in ground truth."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        all_ids = [e["event_id"] for e in gt["entries"]]
        assert len(all_ids) == len(set(all_ids)), (
            f"Duplicate event IDs found: {len(all_ids)} total, {len(set(all_ids))} unique"
        )


def test_no_contradictory_classifications():
    """No event has contradictory classification-category combinations."""
    import tempfile, os, json
    from sentinelforge.datasets.generator import DatasetGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)

        for e in gt["entries"]:
            classification = e["classification"]
            cats = set(e.get("expected_detection_categories", []))

            if classification == "benign":
                attack_cats = {
                    "failed_login_burst", "password_spray", "c2_beacon",
                    "suspicious_processtree", "t1059.001", "t1204.002",
                }
                assert not (cats & attack_cats), (
                    f"{e['event_id']}: benign event has attack categories {cats}"
                )
            elif classification == "suspicious":
                # Suspicious events should have at least one attack category,
                # UNLESS they're contextual/corroborating evidence (e.g., a
                # successful login in a brute-force scenario).
                if not cats:
                    etype = e.get("event_type", "")
                    assert etype == "auth.login.success", (
                        f"{e['event_id']}: suspicious event with no categories "
                        "and is not contextual evidence"
                    )


# ---------------------------------------------------------------------------
# Sysmon normalization through the actual normalizer (M8.3.2)
# ---------------------------------------------------------------------------

def _make_sysmon_event_v2(event_id: int, timestamp: str, computer: str,
                          data_fields: list[tuple[str, str]]) -> dict:
    """Build a Sysmon-style event dict."""
    data = [{"Name": k, "#text": v} for k, v in data_fields]
    return {
        "Event": {
            "System": {
                "Provider": {"Name": "Microsoft-Windows-Sysmon"},
                "EventID": event_id,
                "TimeCreated": {"SystemTime": timestamp},
                "Computer": computer,
            },
            "EventData": {"Data": data},
        }
    }


def test_sysmon_normalize_event_id_1_process_create():
    """Event ID 1 through SysmonReader → normalizer: process fields extracted."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader
    from sentinelforge.ingestion.normalizer import normalize

    event = _make_sysmon_event_v2(
        event_id=1,
        timestamp="2024-01-15T08:00:00Z",
        computer="HOST-01",
        data_fields=[
            ("Image", "C:\\\\Windows\\\\System32\\\\powershell.exe"),
            ("CommandLine", "powershell.exe -ExecutionPolicy Bypass"),
            ("User", "DOMAIN\\\\user"),
            ("ProcessId", "1234"),
            ("ParentProcessId", "5678"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        raw_records = list(reader.read(p))
        assert len(raw_records) == 1

        nev = normalize(raw_records[0], source="sysmon")

        # Timestamp and hostname extraction
        assert nev.timestamp == "2024-01-15T08:00:00+00:00"
        assert nev.host == "HOST-01"
        assert nev.source == "sysmon"

        # Process fields extracted
        assert nev.process is not None
        assert nev.process.pid == 1234
        assert nev.process.ppid == 5678
        assert nev.process.name == "C:\\\\Windows\\\\System32\\\\powershell.exe"
        assert nev.process.path == "C:\\\\Windows\\\\System32\\\\powershell.exe"
        assert nev.process.command_line == "powershell.exe -ExecutionPolicy Bypass"
        assert nev.process.user == "DOMAIN\\\\user"

        # Raw source event preserved
        assert nev.raw == event


def test_sysmon_normalize_event_id_3_network_connection():
    """Event ID 3 through SysmonReader → normalizer: network fields in raw only.

    The normalizer extracts process fields for Sysmon events (based on Image
    field presence) but does NOT map Sysmon network EventData fields
    (SourceIp, DestinationIp, DestinationPort, Protocol) to NormalizedEvent
    network fields. This is a documented limitation — raw data is preserved.
    """
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader
    from sentinelforge.ingestion.normalizer import normalize

    event = _make_sysmon_event_v2(
        event_id=3,
        timestamp="2024-01-15T08:01:00Z",
        computer="HOST-01",
        data_fields=[
            ("SourceIp", "10.0.0.5"),
            ("DestinationIp", "198.51.100.42"),
            ("DestinationPort", "4433"),
            ("Protocol", "tcp"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        raw_records = list(reader.read(p))
        assert len(raw_records) == 1

        nev = normalize(raw_records[0], source="sysmon")

        # Timestamp and hostname extraction
        assert nev.timestamp == "2024-01-15T08:01:00+00:00"
        assert nev.host == "HOST-01"
        assert nev.source == "sysmon"

        # No Image field → process info object exists but all fields are None
        assert nev.process is not None
        assert nev.process.pid is None
        assert nev.process.name is None
        assert nev.process.command_line is None

        # Network fields NOT mapped to NormalizedEvent.network (limitation)
        assert nev.network is None

        # Raw source event preserved — network data accessible in raw
        assert nev.raw == event
        raw_fields = {
            d["Name"]: d["#text"]
            for d in nev.raw["Event"]["EventData"]["Data"]
        }
        assert raw_fields["DestinationIp"] == "198.51.100.42"
        assert raw_fields["DestinationPort"] == "4433"
        assert raw_fields["Protocol"] == "tcp"


def test_sysmon_normalize_event_id_11_file_create():
    """Event ID 11 through SysmonReader → normalizer: file data in raw only.

    File Create EventData (TargetFilename, CreationUtcTime) is NOT mapped to
    any NormalizedEvent field. Raw data is preserved. This is a documented
    limitation.
    """
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader
    from sentinelforge.ingestion.normalizer import normalize

    event = _make_sysmon_event_v2(
        event_id=11,
        timestamp="2024-01-15T08:02:00Z",
        computer="HOST-01",
        data_fields=[
            ("TargetFilename", "C:\\\\Users\\\\user\\\\Downloads\\\\payload.ps1"),
            ("CreationUtcTime", "2024-01-15T08:02:00Z"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        raw_records = list(reader.read(p))
        assert len(raw_records) == 1

        nev = normalize(raw_records[0], source="sysmon")

        assert nev.timestamp == "2024-01-15T08:02:00+00:00"
        assert nev.host == "HOST-01"
        assert nev.source == "sysmon"

        # No Image field → process info object exists but all fields are None
        assert nev.process is not None
        assert nev.process.pid is None
        assert nev.process.name is None

        assert nev.network is None

        # Raw preserved — file data accessible in raw
        assert nev.raw == event
        raw_fields = {
            d["Name"]: d["#text"]
            for d in nev.raw["Event"]["EventData"]["Data"]
        }
        assert raw_fields["TargetFilename"] == (
            "C:\\\\Users\\\\user\\\\Downloads\\\\payload.ps1"
        )
        assert raw_fields["CreationUtcTime"] == "2024-01-15T08:02:00Z"


def test_sysmon_normalize_event_id_22_dns_query():
    """Event ID 22 through SysmonReader → normalizer: DNS data in raw only.

    DNS Query EventData (QueryName, QueryType, QueryResults) is NOT mapped to
    any NormalizedEvent field. Raw data is preserved. This is a documented
    limitation.
    """
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader
    from sentinelforge.ingestion.normalizer import normalize

    event = _make_sysmon_event_v2(
        event_id=22,
        timestamp="2024-01-15T08:03:00Z",
        computer="HOST-01",
        data_fields=[
            ("QueryName", "evil.example.com"),
            ("QueryType", "A"),
            ("QueryResults", "198.51.100.42"),
        ],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        raw_records = list(reader.read(p))
        assert len(raw_records) == 1

        nev = normalize(raw_records[0], source="sysmon")

        assert nev.timestamp == "2024-01-15T08:03:00+00:00"
        assert nev.host == "HOST-01"
        assert nev.source == "sysmon"

        # No Image field → process info object exists but all fields are None
        assert nev.process is not None
        assert nev.process.pid is None
        assert nev.process.name is None

        assert nev.network is None

        # Raw preserved — DNS data accessible in raw
        assert nev.raw == event
        raw_fields = {
            d["Name"]: d["#text"]
            for d in nev.raw["Event"]["EventData"]["Data"]
        }
        assert raw_fields["QueryName"] == "evil.example.com"
        assert raw_fields["QueryType"] == "A"
        assert raw_fields["QueryResults"] == "198.51.100.42"


def test_sysmon_normalize_timestamp_nested_systemtime():
    """Sysmon TimeCreated as nested {\"SystemTime\": \"...\"} dict is extracted."""
    import tempfile, os, json
    from sentinelforge.ingestion.reader import SysmonReader
    from sentinelforge.ingestion.normalizer import normalize

    event = _make_sysmon_event_v2(
        event_id=1,
        timestamp="2024-01-15T08:00:00Z",
        computer="HOST-01",
        data_fields=[("Image", "C:\\\\Windows\\\\System32\\\\calc.exe")],
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "test.evt")
        with open(p, "w") as f:
            f.write(json.dumps(event) + "\n")
        reader = SysmonReader()
        raw_records = list(reader.read(p))
        nev = normalize(raw_records[0], source="sysmon")
        assert nev.timestamp == "2024-01-15T08:00:00+00:00"


def test_password_spray_rule_evidence_set_equality():
    """PasswordSprayRule evidence: exact event-ID set verification.

    Verifies that:
    - All expected password_spray events are detected (no false negatives)
    - All detected events are expected password_spray events or attribution errors
    - No duplicate detection references inflate counts
    - Attribution errors (st-007 failed_login_burst events) are tracked separately
    """
    import json, sqlite3

    with open("data/generated/event_ground_truth.json") as f:
        egt = json.load(f)

    entries = {e["event_id"]: e for e in egt["entries"]}

    # Expected password_spray events from ground truth
    expected_ps = set()
    for eid, e in entries.items():
        cats = e.get("expected_detection_categories", [])
        if "password_spray" in cats and e["classification"] == "suspicious":
            expected_ps.add(eid)

    # Detected by PasswordSprayRule from database
    conn = sqlite3.connect("data/generated/sentinelforge_eval.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT e.event_id
        FROM evidence e
        JOIN detections d ON e.detection_id = d.detection_id
        WHERE d.rule_id = 'sentinelforge.detection.password_spray'
    """)
    detected_ps = {row[0] for row in cur.fetchall()}
    conn.close()

    # Set operations
    intersection = expected_ps & detected_ps
    missing = expected_ps - detected_ps
    extra = detected_ps - expected_ps

    # All expected events must be detected
    assert len(missing) == 0, (
        f"{len(missing)} expected password_spray events not detected: {sorted(missing)[:5]}"
    )

    # All expected events are in the intersection
    assert len(intersection) == len(expected_ps), (
        f"Expected {len(expected_ps)} events detected, got {len(intersection)}"
    )

    # Extra detections must all be attribution errors (suspicious, wrong category)
    for eid in extra:
        e = entries.get(eid, {})
        assert e.get("classification") == "suspicious", (
            f"Extra detection {eid} is not suspicious: {e.get('classification')}"
        )
        assert "password_spray" not in e.get("expected_detection_categories", []), (
            f"Extra detection {eid} already has password_spray category"
        )

    # Report results
    print(f"\nPasswordSprayRule Evidence Verification:")
    print(f"  Expected: {len(expected_ps)}")
    print(f"  Detected: {len(detected_ps)}")
    print(f"  Intersection: {len(intersection)}")
    print(f"  Missing: {len(missing)}")
    print(f"  Extra (attribution errors): {len(extra)}")
    print(f"  Recall: {len(intersection)}/{len(expected_ps)} = {len(intersection)/len(expected_ps):.4f}")

