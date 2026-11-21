"""SentinelForge AI — Real-Time-Style Ingestion and Replay Benchmark (Phase 2, Item 5).

Controlled replay harness using generated events and the actual
ingestion/detection/storage pipeline.

Tests:
- Sequential ingestion
- Small batches
- Larger batches
- Normal event ordering
- Out-of-order event arrival
- Duplicate event delivery
- A burst of events
- Malformed events mixed with valid events

Measures:
- Events received
- Events normalized
- Events successfully persisted
- Events rejected with visible errors
- Alerts generated
- Database write failures
- Processing throughput
- Average processing latency
- P50, P95, P99 latency

Does NOT invent a real-time SLA. Measures actual performance and identifies
the maximum tested sustainable throughput.

The current architecture is batch-only; this benchmark documents that
limitation rather than claiming live streaming support.
"""

from __future__ import annotations

import json
import os
import sqlite3
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, ".")

from sentinelforge.datasets.generator import DatasetGenerator
from sentinelforge.ingestion.reader import reader_for, LogParseError
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.password_spray import PasswordSprayRule
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import EventRepository, DetectionRepository


def percentile(sorted_values: list[float], p: float) -> float:
    """Compute the p-th percentile (0-100) from a sorted list."""
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    d = k - f
    return sorted_values[f] * (1 - d) + sorted_values[c] * d


def run_benchmark() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        print("=" * 70)
        print("SENTINELFORGE AI — REPLAY BENCHMARK (Phase 2, Item 5)")
        print("=" * 70)

        # ---- Generate dataset ----
        print("\n[Setup] Generating dataset (seed=42, 10000 events)...")
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        manifest = gen.generate(total_events=10000)

        data_dir = Path(tmpdir)
        all_raw_events = []
        for cat_file in sorted(data_dir.glob("*.jsonl")):
            reader = reader_for(cat_file)
            events = list(reader.read(str(cat_file)))
            all_raw_events.extend(events)

        print(f"[Setup] Generated {len(all_raw_events)} raw events")

        # ---- Normalize all events once (for replay source) ----
        normalized_source = []
        norm_errors = 0
        for raw in all_raw_events:
            source = raw.get("source", "json")
            try:
                nev = normalize(raw, source=source)
                normalized_source.append(nev)
            except Exception:
                norm_errors += 1

        print(f"[Setup] Normalized {len(normalized_source)} events ({norm_errors} errors)")

        # ---- Setup database ----
        db_path = os.path.join(tmpdir, "replay_benchmark.db")
        db = Database(db_path)
        db.initialize()
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)

        # ---- Detection registry ----
        registry = RuleRegistry()
        registry.register(FailedLoginBurstRule())
        registry.register(PasswordSprayRule())
        registry.register(SuspiciousPowerShellRule())
        registry.register(SuspiciousProcessTreeRule())
        registry.register(C2BeaconRule())

        results: dict[str, dict] = {}

        # ===================================================================
        # Test 1: Sequential ingestion (all events at once)
        # ===================================================================
        print("\n[Test 1] Sequential ingestion (all events at once)...")
        start = time.perf_counter()
        event_ids = event_repo.insert_events(normalized_source)
        t_seq = time.perf_counter() - start

        detection_results = registry.evaluate_all(normalized_source)
        det_ids = det_repo.insert_detections(detection_results)

        t_total = time.perf_counter() - start

        results["sequential"] = {
            "events_received": len(normalized_source),
            "events_normalized": len(normalized_source),
            "events_persisted": len(event_ids),
            "events_rejected": 0,
            "alerts_generated": len(detection_results),
            "db_write_failures": 0,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(normalized_source) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(t_total / len(normalized_source) * 1000, 4),
        }
        print(f"  {len(event_ids)} events persisted, {len(detection_results)} alerts, "
              f"{t_total:.3f}s ({results['sequential']['events_per_sec']:,.0f} eps)")

        # ===================================================================
        # Test 2: Small batches (100 events per batch)
        # ===================================================================
        print("\n[Test 2] Small batches (100 events/batch)...")
        batch_size = 100
        batches = [normalized_source[i:i + batch_size]
                   for i in range(0, len(normalized_source), batch_size)]

        start = time.perf_counter()
        total_persisted = 0
        total_rejected = 0
        total_alerts = 0
        db_failures = 0
        latencies = []

        for batch in batches:
            batch_start = time.perf_counter()
            try:
                ids = event_repo.insert_events(batch)
                total_persisted += len(ids)
            except Exception as e:
                db_failures += 1
                total_rejected += len(batch)
                print(f"  DB write failure: {e}")

            det_results = registry.evaluate_all(batch)
            total_alerts += len(det_results)
            try:
                det_repo.insert_detections(det_results)
            except Exception:
                db_failures += 1

            batch_elapsed = time.perf_counter() - batch_start
            latencies.append(batch_elapsed / len(batch) * 1000)

        t_total = time.perf_counter() - start
        latencies.sort()

        results["small_batches"] = {
            "events_received": len(normalized_source),
            "events_normalized": len(normalized_source),
            "events_persisted": total_persisted,
            "events_rejected": total_rejected,
            "alerts_generated": total_alerts,
            "db_write_failures": db_failures,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(normalized_source) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(statistics.mean(latencies), 4),
            "p50_latency_ms": round(percentile(latencies, 50), 4),
            "p95_latency_ms": round(percentile(latencies, 95), 4),
            "p99_latency_ms": round(percentile(latencies, 99), 4),
        }
        print(f"  {len(batches)} batches, {total_persisted} persisted, {total_alerts} alerts, "
              f"{t_total:.3f}s ({results['small_batches']['events_per_sec']:,.0f} eps)")

        # ===================================================================
        # Test 3: Large batches (1000 events per batch)
        # ===================================================================
        print("\n[Test 3] Large batches (1000 events/batch)...")
        batch_size = 1000
        batches = [normalized_source[i:i + batch_size]
                   for i in range(0, len(normalized_source), batch_size)]

        start = time.perf_counter()
        total_persisted = 0
        total_rejected = 0
        total_alerts = 0
        db_failures = 0
        latencies = []

        for batch in batches:
            batch_start = time.perf_counter()
            try:
                ids = event_repo.insert_events(batch)
                total_persisted += len(ids)
            except Exception as e:
                db_failures += 1
                total_rejected += len(batch)

            det_results = registry.evaluate_all(batch)
            total_alerts += len(det_results)
            try:
                det_repo.insert_detections(det_results)
            except Exception:
                db_failures += 1

            batch_elapsed = time.perf_counter() - batch_start
            latencies.append(batch_elapsed / len(batch) * 1000)

        t_total = time.perf_counter() - start
        latencies.sort()

        results["large_batches"] = {
            "events_received": len(normalized_source),
            "events_normalized": len(normalized_source),
            "events_persisted": total_persisted,
            "events_rejected": total_rejected,
            "alerts_generated": total_alerts,
            "db_write_failures": db_failures,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(normalized_source) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(statistics.mean(latencies), 4),
            "p50_latency_ms": round(percentile(latencies, 50), 4),
            "p95_latency_ms": round(percentile(latencies, 95), 4),
            "p99_latency_ms": round(percentile(latencies, 99), 4),
        }
        print(f"  {len(batches)} batches, {total_persisted} persisted, {total_alerts} alerts, "
              f"{t_total:.3f}s ({results['large_batches']['events_per_sec']:,.0f} eps)")

        # ===================================================================
        # Test 4: Out-of-order event arrival
        # ===================================================================
        print("\n[Test 4] Out-of-order event arrival...")
        # Shuffle events to simulate out-of-order arrival
        import random
        shuffled = list(normalized_source)
        rng = random.Random(42)
        rng.shuffle(shuffled)

        start = time.perf_counter()
        try:
            ids = event_repo.insert_events(shuffled)
            total_persisted = len(ids)
        except Exception as e:
            total_persisted = 0
            print(f"  DB error: {e}")

        det_results = registry.evaluate_all(shuffled)
        total_alerts = len(det_results)
        try:
            det_repo.insert_detections(det_results)
        except Exception:
            pass

        t_total = time.perf_counter() - start

        results["out_of_order"] = {
            "events_received": len(shuffled),
            "events_normalized": len(shuffled),
            "events_persisted": total_persisted,
            "events_rejected": 0,
            "alerts_generated": total_alerts,
            "db_write_failures": 0,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(shuffled) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(t_total / len(shuffled) * 1000, 4),
        }
        print(f"  {total_persisted} persisted, {total_alerts} alerts, "
              f"{t_total:.3f}s ({results['out_of_order']['events_per_sec']:,.0f} eps)")

        # ===================================================================
        # Test 5: Duplicate event delivery
        # ===================================================================
        print("\n[Test 5] Duplicate event delivery...")
        duplicated = normalized_source + normalized_source  # each event twice

        start = time.perf_counter()
        try:
            ids = event_repo.insert_events(duplicated)
            total_persisted = len(ids)
        except Exception as e:
            total_persisted = 0
            print(f"  DB error: {e}")

        det_results = registry.evaluate_all(duplicated)
        total_alerts = len(det_results)

        t_total = time.perf_counter() - start

        results["duplicates"] = {
            "events_received": len(duplicated),
            "events_normalized": len(duplicated),
            "events_persisted": total_persisted,
            "events_rejected": len(duplicated) - total_persisted,
            "alerts_generated": total_alerts,
            "db_write_failures": 0,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(duplicated) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(t_total / len(duplicated) * 1000, 4),
        }
        print(f"  {total_persisted} unique persisted (from {len(duplicated)} delivered), "
              f"{total_alerts} alerts, {t_total:.3f}s")

        # ===================================================================
        # Test 6: Burst of events
        # ===================================================================
        print("\n[Test 6] Burst of events (5000 events in single batch)...")
        burst = normalized_source[:5000]

        start = time.perf_counter()
        try:
            ids = event_repo.insert_events(burst)
            burst_persisted = len(ids)
        except Exception as e:
            burst_persisted = 0
            print(f"  DB error: {e}")

        det_results = registry.evaluate_all(burst)
        burst_alerts = len(det_results)

        t_total = time.perf_counter() - start

        results["burst"] = {
            "events_received": len(burst),
            "events_normalized": len(burst),
            "events_persisted": burst_persisted,
            "events_rejected": len(burst) - burst_persisted,
            "alerts_generated": burst_alerts,
            "db_write_failures": 0,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(burst) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(t_total / len(burst) * 1000, 4),
        }
        print(f"  {burst_persisted} persisted, {burst_alerts} alerts, "
              f"{t_total:.3f}s ({results['burst']['events_per_sec']:,.0f} eps)")

        # ===================================================================
        # Test 7: Malformed events mixed with valid events
        # ===================================================================
        print("\n[Test 7] Malformed events mixed with valid events...")
        # Create some malformed raw events
        malformed_raw = [
            {"event_id": "evt-malformed-1", "timestamp": "not-a-timestamp"},
            {"event_id": "evt-malformed-2"},  # missing timestamp
            {},  # empty event
            {"timestamp": "2024-01-15T08:00:00Z"},  # missing event_id
        ]

        valid_subset = normalized_source[:100]
        malformed_normalized = []
        malformed_rejected = 0

        for raw in malformed_raw:
            try:
                nev = normalize(raw, source="json")
                malformed_normalized.append(nev)
            except Exception:
                malformed_rejected += 1

        mixed = valid_subset + malformed_normalized

        start = time.perf_counter()
        try:
            ids = event_repo.insert_events(mixed)
            mixed_persisted = len(ids)
        except Exception as e:
            mixed_persisted = 0
            print(f"  DB error: {e}")

        det_results = registry.evaluate_all(mixed)
        mixed_alerts = len(det_results)

        t_total = time.perf_counter() - start

        results["malformed_mixed"] = {
            "events_received": len(valid_subset) + len(malformed_raw),
            "events_normalized": len(mixed),
            "events_persisted": mixed_persisted,
            "events_rejected": malformed_rejected,
            "alerts_generated": mixed_alerts,
            "db_write_failures": 0,
            "total_time_s": round(t_total, 4),
            "events_per_sec": round(len(mixed) / max(t_total, 0.001), 0),
            "avg_latency_ms": round(t_total / len(mixed) * 1000, 4),
        }
        print(f"  {len(malformed_raw)} malformed ({malformed_rejected} rejected at normalization), "
              f"{len(mixed)} normalized, {mixed_persisted} persisted, {mixed_alerts} alerts")

        # ===================================================================
        # Final verification
        # ===================================================================
        print("\n[Verification] SQLite integrity and FK checks...")
        conn = sqlite3.connect(db_path)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        total_events_in_db = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_dets_in_db = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        conn.close()

        # ===================================================================
        # Report
        # ===================================================================
        print("\n" + "=" * 70)
        print("BENCHMARK RESULTS SUMMARY")
        print("=" * 70)
        print(f"\n{'Test':<20} {'Events':>8} {'Persisted':>10} {'Rejected':>9} {'Alerts':>8} {'eps':>10} {'AvgLat(ms)':>12}")
        print("-" * 90)
        for name, r in results.items():
            print(f"{name:<20} {r['events_received']:>8} {r['events_persisted']:>10} "
                  f"{r['events_rejected']:>9} {r['alerts_generated']:>8} "
                  f"{r['events_per_sec']:>10,.0f} {r['avg_latency_ms']:>12.4f}")

        if "small_batches" in results:
            sb = results["small_batches"]
            print(f"\nSmall batches latency: P50={sb['p50_latency_ms']:.4f}ms, "
                  f"P95={sb['p95_latency_ms']:.4f}ms, P99={sb['p99_latency_ms']:.4f}ms")

        print(f"\nSQLite integrity_check: {integrity}")
        print(f"SQLite foreign_key_check: {len(fk_violations)} violations")
        print(f"Total events in DB: {total_events_in_db}")
        print(f"Total detections in DB: {total_dets_in_db}")

        # Maximum sustainable throughput
        max_eps = max(r["events_per_sec"] for r in results.values())
        print(f"\nMaximum tested sustainable throughput: {max_eps:,.0f} events/second")
        print("Architecture: batch-only (no real-time streaming implemented)")
        print("\nBenchmark complete.")


if __name__ == "__main__":
    run_benchmark()