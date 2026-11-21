# SentinelForge AI — Phase 2 Test Preservation Audit

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_PHASE2_TEST_PRESERVATION_AUDIT.md  
**Version:** 1.0.0  
**Status:** Complete — Test preservation audit  
**Test Results:** 275 passed, 0 failed (pytest 8.4.2, Python 3.12.10)

---

## 1. Exact Two Tests That Were Removed

During the Navigator v4.5 schema correction, two existing tests were removed because they asserted the **incorrect** pre-fix behavior:

| Test File | Test Name | Original Assertion | Why Removed |
|---|---|---|---|
| `tests/test_attack_navigator_export.py` | `test_primary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` (top-level boolean) | Asserted `expandedSubtechniques` at top level as boolean `False`, which is incorrect per v4.5 spec |
| `tests/test_attack_navigator_export.py` | `test_secondary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` (top-level boolean) | Same incorrect assertion for secondary layer |

### Original Test Code (Removed)

```python
def test_primary_layer_has_expanded_subtechniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["expandedSubtechniques"] is False

def test_secondary_layer_has_expanded_subtechniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["expandedSubtechniques"] is False
```

---

## 2. Why They Were Removed Instead of Updated

These tests asserted behavior that was **incorrect per the MITRE ATT&CK Navigator v4.5 specification**:

- `expandedSubtechniques` is NOT a top-level property in v4.5 — it belongs inside the `layout` object
- `expandedSubtechniques` is NOT a boolean — it is a string with allowed values `"none"`, `"all"`, or `"annotated"`

The original assertions (`layer["expandedSubtechniques"] is False`) would **fail** against the corrected v4.5-compliant output because:
1. `expandedSubtechniques` no longer exists at the top level (KeyError)
2. Even if it did, the value would be `"none"` (string), not `False` (boolean)

Rather than keeping tests that assert incorrect behavior, they were replaced with corrected versions that assert the proper v4.5 schema.

---

## 3. Equivalent Tests Now Validate the Corrected v4.5 Schema

The original test names have been **restored** with corrected assertions:

| Restored Test Name | Original Assertion | Corrected Assertion |
|---|---|---|
| `test_primary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` | `"expandedSubtechniques" not in layer` AND `layer["layout"]["expandedSubtechniques"] == "none"` AND `isinstance(val, str)` |
| `test_secondary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` | `"expandedSubtechniques" not in layer` AND `layer["layout"]["expandedSubtechniques"] == "none"` AND `isinstance(val, str)` |

The corrected assertions are **stricter** than the originals — they verify:
1. `expandedSubtechniques` is NOT at the top level (schema compliance)
2. `expandedSubtechniques` IS inside `layout` (correct v4.5 location)
3. `expandedSubtechniques` is a string (correct type)
4. `expandedSubtechniques` equals `"none"` (correct enum value)

---

## 4. Relevant Test Function Names — Before and After

| Phase | Test Function Name | What It Asserted |
|---|---|---|
| Before (v4.4/incorrect v4.5) | `test_primary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` (top-level boolean) |
| After (v4.5/corrected) | `test_primary_layer_has_expanded_subtechniques` | `"expandedSubtechniques" not in layer` AND `layer["layout"]["expandedSubtechniques"] == "none"` |
| Before (v4.4/incorrect v4.5) | `test_secondary_layer_has_expanded_subtechniques` | `layer["expandedSubtechniques"] is False` (top-level boolean) |
| After (v4.5/corrected) | `test_secondary_layer_has_expanded_subtechniques` | `"expandedSubtechniques" not in layer` AND `layer["layout"]["expandedSubtechniques"] == "none"` |

Additional schema tests added alongside the restored tests:

| Test Function | What It Validates |
|---|---|
| `test_primary_layer_expanded_subtechniques_in_layout` | `expandedSubtechniques` is NOT at top level AND IS inside `layout` with value `"none"` |
| `test_secondary_layer_expanded_subtechniques_in_layout` | Same for secondary layer |
| `test_primary_layer_select_visible_techniques_top_level` | `selectVisibleTechniques` is top-level `bool`, value `True` |
| `test_secondary_layer_select_visible_techniques_top_level` | Same for secondary layer |
| `test_primary_layer_expanded_subtechniques_is_string` | `expandedSubtechniques` is a `str`, value in `("none", "all", "annotated")` |
| `test_secondary_layer_expanded_subtechniques_is_string` | Same for secondary layer |

---

## 5. Confirmation: No Regression Test Was Deleted, Skipped, Weakened, or Marked xfail

| Check | Result |
|---|---|
| Original 208 pre-existing tests | All present, all passing |
| Phase 1 ATT&CK tests (18) | All present, all passing |
| Phase 2 coverage tests (20) | All present, all passing |
| Phase 2 Navigator tests (29) | All present, all passing |
| Tests marked `skip`, `skipif`, or `xfail` | 0 |
| Tests removed without replacement | 0 (the 2 removed tests were restored with corrected assertions) |
| Detection thresholds altered | 0 |
| Expected outcomes changed | 0 |

### Test Count Reconciliation

| Category | Test Count |
|---|---|
| Pre-existing regression tests | 208 |
| Phase 1 ATT&CK catalogue tests | 18 |
| Phase 2 coverage tests | 20 |
| Phase 2 Navigator tests | 29 |
| **Total** | **275** |

---

## 6. Actual Pytest Collection Count and Final Test Inventory

```
275 passed in 53.30s
```

### Complete Test Inventory by File

| Test File | Test Count |
|---|---|
| `tests/test_ingestion.py` | Ingestion tests (pre-existing) |
| `tests/test_detection.py` | Detection tests (pre-existing) |
| `tests/test_detection_rules.py` | Detection rule tests (pre-existing) |
| `tests/test_beacon.py` | Beacon tests (pre-existing) |
| `tests/test_storage.py` | Storage tests (pre-existing) |
| `tests/test_risk.py` | Risk tests (pre-existing) |
| `tests/test_datasets.py` | Dataset tests (pre-existing) |
| `tests/test_password_spray.py` | Password spray tests (pre-existing) |
| `tests/test_evaluation.py` | Evaluation tests (pre-existing) |
| `tests/test_attack_catalogue.py` | 18 ATT&CK catalogue tests |
| `tests/test_attack_coverage.py` | 20 coverage calculation tests |
| `tests/test_attack_navigator_export.py` | 29 Navigator export tests |
| **Total** | **275** |

### Navigator Export Test Breakdown (29 tests)

| Category | Tests |
|---|---|
| Navigator format validation | 10 |
| Determinism | 2 |
| Version compatibility (v4.5) | 3 |
| v4.5 format (selectVisibleTechniques, expandedSubtechniques, versions) | 8 |
| v4.5 schema (expandedSubtechniques in layout, string type, enum) | 6 |
| **Total** | **29** |

---

## 7. Verification: Generated Output Validation (Not Malformed Input Rejection)

The `sentinelforge/attack/navigator.py` module contains **no input validation function**. It provides:

| Function | Purpose |
|---|---|
| `generate_primary_layer()` | Generates primary Navigator layer (5 implemented mappings) |
| `generate_secondary_layer()` | Generates secondary Navigator layer (69-entry readiness inventory) |
| `_write_json()` | Writes deterministic JSON to file |
| `compute_sha256()` | Computes SHA-256 hash of a file |

The existing Navigator tests verify that the **generated output** conforms to the v4.5 specification — they do **not** test rejection of malformed external JSON input. This is an intentional design choice: the navigator module is a generator, not a validator.

The following schema properties are verified on generated output:

| Coverage Area | Test(s) | What Is Verified |
|---|---|---|
| `expandedSubtechniques` inside `layout` | `test_primary_layer_expanded_subtechniques_in_layout`, `test_secondary_layer_expanded_subtechniques_in_layout`, `test_primary_layer_has_expanded_subtechniques`, `test_secondary_layer_has_expanded_subtechniques` | Generated layer has `expandedSubtechniques` inside `layout`, not at top level |
| String type enforcement | `test_primary_layer_expanded_subtechniques_is_string`, `test_secondary_layer_expanded_subtechniques_is_string` | Generated value is `str`, not `bool` |
| Valid enum values | `test_primary_layer_expanded_subtechniques_is_string`, `test_secondary_layer_expanded_subtechniques_is_string` | Generated value is `"none"` |
| Top-level property rejection | `test_primary_layer_has_expanded_subtechniques`, `test_secondary_layer_has_expanded_subtechniques` | Generated output does NOT have `expandedSubtechniques` at top level |
| `selectVisibleTechniques` at top level | `test_primary_layer_select_visible_techniques_top_level`, `test_secondary_layer_select_visible_techniques_top_level` | Generated output has `selectVisibleTechniques` at top level as `bool` |

### What Is NOT Tested

The following are **not** tested because no input validation function exists in the codebase:

| Scenario | Test | Reason |
|---|---|---|
| `expandedSubtechniques` at top level in external JSON | None | No input validation function exists |
| Boolean `expandedSubtechniques` in external JSON | None | No input validation function exists |
| Invalid enum value in external JSON | None | No input validation function exists |
| Missing `layout` in external JSON | None | No input validation function exists |
| Missing `expandedSubtechniques` in external JSON | None | No input validation function exists |

### Why No Validator Exists

The navigator module is a **generator**, not a validator. It produces deterministic, schema-compliant JSON output. No external JSON ingestion or validation path exists in the codebase. Adding an input validator would be unnecessary infrastructure with no consumer — no code path reads external Navigator layer files for processing.

### Correct Statement

The existing tests verify that **generated Navigator layer output** conforms to the v4.5 specification. They do **not** test rejection of malformed external input, because no input validation function exists and none is needed.

---
---

## 8. Complete Test Suite Result

```
275 passed in 59.36s
```

All 275 tests pass with zero failures and zero warnings.

---

## 9. Test Preservation Conclusion

| Question | Answer |
|---|---|
| Were any existing tests removed without replacement? | No — 2 tests were removed and restored with corrected assertions |
| Were any existing tests weakened? | No — corrected assertions are stricter than originals |
| Were any tests skipped, xfailed, or marked to fail? | No — 0 skipped, 0 xfailed |
| Were detection thresholds or expected outcomes changed? | No |
| Is equivalent or better coverage preserved? | Yes — corrected assertions validate the proper v4.5 schema with type and enum checking |

The two removed tests were testing **incorrect behavior** (top-level boolean `False` for `expandedSubtechniques`). They were restored with the **same test function names** but **corrected assertions** that validate the proper v4.5 schema location (`layout.expandedSubtechniques` as string `"none"`). No regression coverage was lost.

---