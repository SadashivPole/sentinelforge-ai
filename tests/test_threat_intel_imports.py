"""Tests for the bounded local IOC import workflow (sentinelforge.threat_intel.imports).

Scenarios:
1. Valid JSON import (single record, list, and {"indicators": [...]} wrapper)
2. Valid CSV import
3. Rejected: missing source_name, oversized file, non-UTF-8, bad JSON/CSV
4. Rejected per-record: invalid type, missing value, invalid syntax
5. Duplicate handling within a single import
6. Record count limit enforced
7. Canonicalization (lowercase hash/domain, trimmed whitespace)
8. Confidence parsing and bounds
9. Import result carries imported + rejected records
10. Safe deserialization (json only; no code execution)
"""

from __future__ import annotations

import json

import pytest

from sentinelforge.threat_intel.imports import (
    ImportedIOC,
    ImportResult,
    RejectedRecord,
    import_iocs,
)
from sentinelforge.threat_intel.validator import ValidationError


def _json(records) -> bytes:
    return json.dumps(records).encode("utf-8")


def _csv(header: str, rows: list[str]) -> bytes:
    return (header + "\n" + "\n".join(rows)).encode("utf-8")


# --------------------------------------------------------------------------- #
# Valid imports
# --------------------------------------------------------------------------- #
def test_import_json_single_record() -> None:
    result = import_iocs(
        _json(
            {
                "indicator_type": "ipv4",
                "indicator_value": "192.168.1.1",
                "source_name": "intel-src",
                "confidence": 80,
            }
        ),
        "intel-src",
    )
    assert len(result.imported) == 1
    assert len(result.rejected) == 0
    ioc = result.imported[0]
    assert isinstance(ioc, ImportedIOC)
    assert ioc.indicator_value == "192.168.1.1"
    assert ioc.indicator_type == "ipv4"
    assert ioc.source_name == "intel-src"
    assert ioc.confidence == 80
    assert ioc.validation_status == "valid"
    assert ioc.provenance == "import:intel-src"


def test_import_json_list() -> None:
    result = import_iocs(
        _json(
            [
                {
                    "indicator_type": "sha256",
                    "indicator_value": "A" * 64,
                    "source_name": "s",
                },
                {
                    "indicator_type": "domain",
                    "indicator_value": "Example.COM",
                    "source_name": "s",
                },
            ]
        ),
        "s",
    )
    assert len(result.imported) == 2
    assert result.imported[0].indicator_value == "a" * 64  # canonicalized lowercase
    assert result.imported[1].indicator_value == "example.com"  # canonicalized


def test_import_json_indicators_wrapper() -> None:
    result = import_iocs(
        _json(
            {
                "indicators": [
                    {
                        "indicator_type": "ipv6",
                        "indicator_value": "::1",
                        "source_name": "s",
                    }
                ]
            }
        ),
        "s",
    )
    assert len(result.imported) == 1


def test_import_csv() -> None:
    data = _csv(
        "indicator_type,indicator_value,source_name,confidence,context",
        [
            "url,https://example.com/malware,sr,70,downloader",
            "ipv4,  10.0.0.5  ,sr,,",
        ],
    )
    result = import_iocs(data, "sr")
    assert len(result.imported) == 2
    assert len(result.rejected) == 0
    assert result.imported[0].indicator_value == "https://example.com/malware"
    assert result.imported[0].confidence == 70
    assert result.imported[1].indicator_value == "10.0.0.5"
    assert result.imported[1].confidence is None


# --------------------------------------------------------------------------- #
# Rejections: file-level
# --------------------------------------------------------------------------- #
def test_import_missing_source_name() -> None:
    with pytest.raises(ValueError, match="source_name is required"):
        import_iocs(
            _json([{"indicator_type": "ipv4", "indicator_value": "1.2.3.4"}]), ""
        )


def test_import_file_too_large() -> None:
    _json(
        [{"indicator_type": "ipv4", "indicator_value": "1.2.3.4", "source_name": "s"}]
    )
    big = b"x" * (5 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="too large"):
        import_iocs(big, "s")


def test_import_non_utf8_rejected() -> None:
    with pytest.raises(ValueError, match="UTF-8"):
        import_iocs(b"\xff\xfe\x00invalid", "s")


def test_import_invalid_json_rejected() -> None:
    with pytest.raises(ValueError):
        import_iocs(b"{not valid json", "s")


def test_import_invalid_json_shape_rejected() -> None:
    # An empty JSON object yields a single record missing indicator_type,
    # which is rejected as malformed (not executed).
    result = import_iocs(b"{}", "s")
    assert len(result.imported) == 0
    assert len(result.rejected) == 1
    assert "missing or invalid indicator_type" in result.rejected[0].reason


def test_import_empty_json_array() -> None:
    result = import_iocs(b"[]", "s")
    assert len(result.imported) == 0
    assert len(result.rejected) == 0


# --------------------------------------------------------------------------- #
# Rejections: per-record
# --------------------------------------------------------------------------- #
def test_import_rejects_invalid_type() -> None:
    result = import_iocs(
        _json(
            [{"indicator_type": "md5", "indicator_value": "abcd", "source_name": "s"}]
        ),
        "s",
    )
    assert len(result.imported) == 0
    assert len(result.rejected) == 1
    assert "indicator_type" in result.rejected[0].reason


def test_import_rejects_missing_value() -> None:
    result = import_iocs(
        _json([{"indicator_type": "ipv4", "indicator_value": "", "source_name": "s"}]),
        "s",
    )
    assert len(result.imported) == 0
    assert len(result.rejected) == 1
    assert "indicator_value" in result.rejected[0].reason


@pytest.mark.parametrize(
    "record",
    [
        {"indicator_type": "ipv4", "indicator_value": "999.999.999.999"},
        {"indicator_type": "domain", "indicator_value": "-bad.com"},
        {"indicator_type": "sha256", "indicator_value": "not-a-hash"},
        {"indicator_type": "url", "indicator_value": "not a url"},
        {"indicator_type": "ipv6", "indicator_value": "zzz::1"},
    ],
)
def test_import_rejects_invalid_syntax(record: dict) -> None:
    record["source_name"] = "s"
    result = import_iocs(_json([record]), "s")
    assert len(result.imported) == 0
    assert len(result.rejected) == 1


# --------------------------------------------------------------------------- #
# Duplicates within an import
# --------------------------------------------------------------------------- #
def test_import_dedupes_within_import() -> None:
    rec = {"indicator_type": "ipv4", "indicator_value": "1.2.3.4", "source_name": "s"}
    result = import_iocs(_json([rec, rec, rec]), "s")
    assert len(result.imported) == 1
    assert len(result.rejected) == 2
    assert all("duplicate" in r.reason for r in result.rejected)


def test_import_case_insensitive_dedup() -> None:
    result = import_iocs(
        _json(
            [
                {
                    "indicator_type": "sha256",
                    "indicator_value": "A" * 64,
                    "source_name": "s",
                },
                {
                    "indicator_type": "sha256",
                    "indicator_value": "a" * 64,
                    "source_name": "s",
                },
            ]
        ),
        "s",
    )
    assert len(result.imported) == 1
    assert len(result.rejected) == 1


# --------------------------------------------------------------------------- #
# Limits
# --------------------------------------------------------------------------- #
def test_import_record_count_limit() -> None:
    records = [
        {"indicator_type": "ipv4", "indicator_value": f"10.0.0.{i}", "source_name": "s"}
        for i in range(10001)
    ]
    with pytest.raises(ValueError, match="Too many records"):
        import_iocs(_json(records), "s")


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("90", 90),
        ("0", 0),
        ("100", 100),
        ("", None),
        (None, None),
        ("150", None),
        ("-5", None),
        ("abc", None),
    ],
)
def test_import_confidence_parsing(raw: object, expected: object) -> None:
    result = import_iocs(
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "1.2.3.4",
                    "source_name": "s",
                    "confidence": raw,
                }
            ]
        ),
        "s",
    )
    assert len(result.imported) == 1
    assert result.imported[0].confidence == expected


# --------------------------------------------------------------------------- #
# Result structure + safe deserialization
# --------------------------------------------------------------------------- #
def test_import_result_structure() -> None:
    result = import_iocs(
        _json(
            [
                {
                    "indicator_type": "domain",
                    "indicator_value": "example.com",
                    "source_name": "s",
                },
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "bad.ip",
                    "source_name": "s",
                },
            ]
        ),
        "s",
    )
    assert isinstance(result, ImportResult)
    assert result.source_name == "s"
    assert len(result.imported) == 1
    assert len(result.rejected) == 1
    assert isinstance(result.rejected[0], RejectedRecord)
    assert result.rejected[0].line_number == 2


def test_import_no_code_execution() -> None:
    # Indicator values are treated as data and validated, never executed.
    result = import_iocs(
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "__import__('os')",
                    "source_name": "s",
                }
            ]
        ),
        "s",
    )
    assert len(result.imported) == 0
    assert len(result.rejected) == 1
    assert "Invalid IPv4" in result.rejected[0].reason


def test_validation_error_is_value_error() -> None:
    assert issubclass(ValidationError, ValueError)
