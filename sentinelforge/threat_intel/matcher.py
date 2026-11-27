"""IOC matching engine.

Matches stored indicators against previously ingested telemetry using
explicit normalized-field extraction:

* IPv4/IPv6 — exact match against source/destination IP fields.
* SHA256 — exact match against the process hash field.
* domain / URL — conservative normalized match against structured fields
  extracted from the raw JSON payload (never indiscriminate substring
  searching of serialized text).

Every match records the indicator, event, matched field/value, source and
match type so analysts can verify each hit.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse, urlunparse

from sentinelforge.storage.schema import IOC, IOCMatch

_IP_FIELDS = (
    "source_address",
    "auth_source_address",
    "network_remote_address",
    "network_local_address",
)

_HASH_FIELDS = ("process_hash_sha256",)

_DOMAIN_KEYS = ("domain", "dns_query", "hostname", "query")

_URL_KEYS = ("url", "uri", "request_uri", "request_url")


def _event_field(event: dict[str, Any], field: str) -> str | None:
    val = event.get(field)
    return str(val) if val is not None else None


def _extract_ips(event: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    for field in _IP_FIELDS:
        val = _event_field(event, field)
        if val:
            ips.append(val)
    return ips


def _extract_hashes(event: dict[str, Any]) -> list[str]:
    hashes: list[str] = []
    for field in _HASH_FIELDS:
        val = _event_field(event, field)
        if val:
            hashes.append(val.lower())
    return hashes


def _extract_json_field(event: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    """Extract candidate string values from the raw JSON payload by key.

    Structured field extraction only — no substring searching of the
    serialized payload. Returns values in document order.
    """
    found: list[str] = []
    raw = event.get("raw")
    if not raw:
        return found
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return found
    if not isinstance(payload, dict):
        return found
    for key in keys:
        val = payload.get(key)
        if isinstance(val, str) and val:
            found.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item:
                    found.append(item)
    return found


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_url(value: str) -> str:
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return value.strip().lower()
    if not parsed.scheme or not parsed.netloc:
        return value.strip().lower()
    netloc = (parsed.hostname or "").lower()
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _ip_field_of(event: dict[str, Any], ip: str) -> str:
    for field in _IP_FIELDS:
        if event.get(field) == ip:
            return field
    return "unknown_ip"


def _make_match_id(prefix: str, indicator_id: str, event_id: str) -> str:
    payload = f"{prefix}|{indicator_id}|{event_id}"
    return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def match_iocs(
    events: list[dict[str, Any]],
    iocs: list[IOC],
    match_id_prefix: str = "match",
) -> list[IOCMatch]:
    """Match IOCs against events.

    Scans each event for the field(s) relevant to each IOC type and returns
    one :class:`IOCMatch` per (indicator, event) pair. Duplicates are
    suppressed. Matching does not modify any event or alert.
    """
    ipv4_iocs = {
        ioc.indicator_value: ioc for ioc in iocs if ioc.indicator_type == "ipv4"
    }
    ipv6_iocs = {
        ioc.indicator_value: ioc for ioc in iocs if ioc.indicator_type == "ipv6"
    }
    sha256_iocs = {
        ioc.indicator_value: ioc for ioc in iocs if ioc.indicator_type == "sha256"
    }
    domain_iocs = {
        _normalize_domain(ioc.indicator_value): ioc
        for ioc in iocs
        if ioc.indicator_type == "domain"
    }
    url_iocs = {
        _normalize_url(ioc.indicator_value): ioc
        for ioc in iocs
        if ioc.indicator_type == "url"
    }

    matches: list[IOCMatch] = []
    seen: set[tuple[str, str]] = set()

    for event in events:
        event_id = event.get("event_id")
        if not event_id:
            continue
        event_timestamp = _event_field(event, "timestamp")

        # IP matching (exact).
        for ip in _extract_ips(event):
            ioc = ipv4_iocs.get(ip) or ipv6_iocs.get(ip)
            if ioc and (ioc.indicator_id, event_id) not in seen:
                seen.add((ioc.indicator_id, event_id))
                matches.append(
                    IOCMatch(
                        match_id=_make_match_id(
                            match_id_prefix, ioc.indicator_id, event_id
                        ),
                        indicator_id=ioc.indicator_id,
                        event_id=event_id,
                        event_timestamp=event_timestamp,
                        matched_field=_ip_field_of(event, ip),
                        matched_value=ip,
                        indicator_source=ioc.source_name,
                        match_type="exact_ip",
                    )
                )

        # Hash matching (exact).
        for h in _extract_hashes(event):
            ioc = sha256_iocs.get(h)
            if ioc and (ioc.indicator_id, event_id) not in seen:
                seen.add((ioc.indicator_id, event_id))
                matches.append(
                    IOCMatch(
                        match_id=_make_match_id(
                            match_id_prefix, ioc.indicator_id, event_id
                        ),
                        indicator_id=ioc.indicator_id,
                        event_id=event_id,
                        event_timestamp=event_timestamp,
                        matched_field="process_hash_sha256",
                        matched_value=h,
                        indicator_source=ioc.source_name,
                        match_type="exact_hash",
                    )
                )

        # Domain matching (conservative, structured extraction).
        for dom in _extract_json_field(event, _DOMAIN_KEYS):
            ndom = _normalize_domain(dom)
            ioc = domain_iocs.get(ndom)
            if ioc and (ioc.indicator_id, event_id) not in seen:
                seen.add((ioc.indicator_id, event_id))
                matches.append(
                    IOCMatch(
                        match_id=_make_match_id(
                            match_id_prefix, ioc.indicator_id, event_id
                        ),
                        indicator_id=ioc.indicator_id,
                        event_id=event_id,
                        event_timestamp=event_timestamp,
                        matched_field="raw_json_domain",
                        matched_value=dom,
                        indicator_source=ioc.source_name,
                        match_type="normalized_domain",
                    )
                )

        # URL matching (conservative, structured extraction).
        for url in _extract_json_field(event, _URL_KEYS):
            nurl = _normalize_url(url)
            ioc = url_iocs.get(nurl)
            if ioc and (ioc.indicator_id, event_id) not in seen:
                seen.add((ioc.indicator_id, event_id))
                matches.append(
                    IOCMatch(
                        match_id=_make_match_id(
                            match_id_prefix, ioc.indicator_id, event_id
                        ),
                        indicator_id=ioc.indicator_id,
                        event_id=event_id,
                        event_timestamp=event_timestamp,
                        matched_field="raw_json_url",
                        matched_value=url,
                        indicator_source=ioc.source_name,
                        match_type="normalized_url",
                    )
                )

    return matches
