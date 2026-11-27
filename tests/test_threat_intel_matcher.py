"""Tests for the IOC matching engine (sentinelforge.threat_intel.matcher).

Scenarios:
1. Exact IPv4/IPv6 match against network/auth address fields
2. Exact SHA256 match against process_hash_sha256
3. Normalized domain match against structured raw-JSON fields
4. Normalized URL match against structured raw-JSON fields
5. No indiscriminate substring matching of serialized raw text
6. One match per (indicator, event); duplicates suppressed
7. Events without an event_id are skipped
8. Empty inputs produce no matches
9. Match records carry all required fields
"""

from __future__ import annotations

from sentinelforge.storage.schema import IOC, IOCMatch
from sentinelforge.threat_intel.matcher import match_iocs


def _ioc(
    indicator_type: str, value: str, source: str = "src", iid: str | None = None
) -> IOC:
    return IOC(
        indicator_id=iid or f"ioc-{indicator_type}-{value}",
        indicator_value=value,
        indicator_type=indicator_type,
        source_name=source,
    )


def _event(
    event_id: str,
    *,
    source_address: str | None = None,
    network_remote_address: str | None = None,
    network_local_address: str | None = None,
    process_hash_sha256: str | None = None,
    raw: dict | None = None,
    timestamp: str = "2026-01-01T00:00:00Z",
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "auth_source_address": source_address,
        "network_remote_address": network_remote_address,
        "network_local_address": network_local_address,
        "process_hash_sha256": process_hash_sha256,
        "raw": raw,
    }


# --------------------------------------------------------------------------- #
# Exact IP matching
# --------------------------------------------------------------------------- #
def test_match_ipv4_exact() -> None:
    events = [_event("evt-1", source_address="192.168.1.10")]
    iocs = [_ioc("ipv4", "192.168.1.10")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1
    m = matches[0]
    assert m.match_type == "exact_ip"
    assert m.matched_value == "192.168.1.10"
    assert m.event_id == "evt-1"
    assert m.indicator_source == "src"


def test_match_ipv6_exact() -> None:
    events = [_event("evt-2", network_remote_address="2001:db8::1")]
    iocs = [_ioc("ipv6", "2001:db8::1")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1
    assert matches[0].match_type == "exact_ip"


def test_match_ip_no_match_when_different() -> None:
    events = [_event("evt-3", source_address="10.0.0.1")]
    iocs = [_ioc("ipv4", "10.0.0.2")]
    assert match_iocs(events, iocs) == []


# --------------------------------------------------------------------------- #
# Exact hash matching
# --------------------------------------------------------------------------- #
def test_match_sha256_exact() -> None:
    h = "a" * 64
    events = [_event("evt-4", process_hash_sha256=h)]
    iocs = [_ioc("sha256", h)]  # IOC values are canonicalized (lowercase) at import
    matches = match_iocs(events, iocs)
    assert len(matches) == 1
    assert matches[0].match_type == "exact_hash"
    assert matches[0].matched_value == h


def test_match_sha256_no_match() -> None:
    events = [_event("evt-5", process_hash_sha256="b" * 64)]
    iocs = [_ioc("sha256", "a" * 64)]
    assert match_iocs(events, iocs) == []


# --------------------------------------------------------------------------- #
# Domain matching (structured, normalized)
# --------------------------------------------------------------------------- #
def test_match_domain_normalized() -> None:
    events = [
        _event("evt-6", raw={"dns_query": "Example.COM"}),
    ]
    iocs = [_ioc("domain", "example.com")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1
    assert matches[0].match_type == "normalized_domain"
    assert matches[0].matched_field == "raw_json_domain"
    assert matches[0].matched_value == "Example.COM"


def test_match_domain_trailing_dot_normalized() -> None:
    events = [_event("evt-7", raw={"hostname": "example.com."})]
    iocs = [_ioc("domain", "example.com")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1


# --------------------------------------------------------------------------- #
# URL matching (structured, normalized)
# --------------------------------------------------------------------------- #
def test_match_url_normalized() -> None:
    # Scheme/host are normalized; the path is case-sensitive, so keep it
    # identical in both IOC and event.
    events = [_event("evt-8", raw={"url": "HTTP://Example.COM/path"})]
    iocs = [_ioc("url", "http://example.com/path")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1
    assert matches[0].match_type == "normalized_url"


# --------------------------------------------------------------------------- #
# No substring / indiscriminate matching
# --------------------------------------------------------------------------- #
def test_no_domain_substring_false_positive() -> None:
    # "evil.com" must not match the payload value "evil.com.attacker.example.net"
    # because we extract structured fields, not substrings of raw text.
    events = [_event("evt-9", raw={"domain": "evil.com.attacker.example.net"})]
    iocs = [_ioc("domain", "evil.com")]
    assert match_iocs(events, iocs) == []


def test_no_raw_text_substring_match() -> None:
    # The raw payload is a dict; we never scan its serialized text for
    # indicator substrings.
    events = [_event("evt-10", raw={"note": "see http://evil.com for details"})]
    iocs = [_ioc("url", "http://evil.com")]
    assert match_iocs(events, iocs) == []


# --------------------------------------------------------------------------- #
# Duplicates suppressed
# --------------------------------------------------------------------------- #
def test_one_match_per_indicator_event() -> None:
    events = [
        _event("evt-11", source_address="1.2.3.4", network_remote_address="1.2.3.4")
    ]
    iocs = [_ioc("ipv4", "1.2.3.4")]
    matches = match_iocs(events, iocs)
    assert len(matches) == 1  # same indicator + same event, deduped


def test_multiple_indicators_same_event() -> None:
    events = [_event("evt-12", source_address="1.2.3.4", process_hash_sha256="a" * 64)]
    iocs = [_ioc("ipv4", "1.2.3.4"), _ioc("sha256", "a" * 64)]
    matches = match_iocs(events, iocs)
    assert len(matches) == 2


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_event_without_id_skipped() -> None:
    events = [{**_event("evt-13"), "event_id": None}]
    iocs = [_ioc("ipv4", "1.2.3.4")]
    assert match_iocs(events, iocs) == []


def test_empty_events() -> None:
    assert match_iocs([], [_ioc("ipv4", "1.2.3.4")]) == []


def test_empty_iocs() -> None:
    assert match_iocs([_event("evt-14")], []) == []


def test_match_record_fields() -> None:
    events = [_event("evt-15", source_address="5.6.7.8")]
    iocs = [_ioc("ipv4", "5.6.7.8", source="intel-feed")]
    matches = match_iocs(events, iocs)
    m = matches[0]
    assert isinstance(m, IOCMatch)
    assert m.match_id.startswith("match-")
    assert m.indicator_id == "ioc-ipv4-5.6.7.8"
    assert m.event_id == "evt-15"
    assert m.matched_field == "auth_source_address"
    assert m.matched_value == "5.6.7.8"
    assert m.indicator_source == "intel-feed"
    assert m.event_timestamp == "2026-01-01T00:00:00Z"
