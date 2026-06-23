"""Data-integrity tests for every ``ConfigRequirements`` declared in the shipped
compliance framework JSONs.

These guard the ~700 constraints added across the frameworks against drift:
- every constraint is well-formed (valid operator, value typed for its operator),
- every constraint targets a check the requirement actually maps (no orphans),
- the region-mute invariant holds (every requirement mapping a region-scoped
  check carries the ``mute_non_default_regions == false`` constraint),
- every framework still parses through its model.
"""

import glob
import json
import pathlib

import pytest

from prowler.lib.check.compliance_models import Compliance, ComplianceFramework

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_COMPLIANCE_DIR = _REPO_ROOT / "prowler" / "compliance"

_VALID_OPERATORS = {"lte", "gte", "eq", "in", "subset", "superset"}
# Checks whose result is untrustworthy when non-default regions are muted.
_REGION_CHECKS = {
    "accessanalyzer_enabled",
    "config_recorder_all_regions_enabled",
    "drs_job_exist",
    "guardduty_delegated_admin_enabled_all_regions",
    "guardduty_is_enabled",
    "securityhub_enabled",
}

_ALL_FILES = sorted(glob.glob(str(_COMPLIANCE_DIR / "**" / "*.json"), recursive=True))


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _requirements(data):
    return data.get("Requirements") or data.get("requirements") or []


def _req_id(req):
    return req.get("Id") or req.get("id")


def _req_checks(req):
    ch = req.get("Checks", req.get("checks"))
    checks = set()
    if isinstance(ch, dict):
        for v in ch.values():
            checks |= set(v or [])
    elif isinstance(ch, list):
        checks |= set(ch)
    return checks


def _req_constraints(req):
    return req.get("ConfigRequirements") or req.get("config_requirements") or []


def _iter_constraints():
    """Yield (file, req_id, checks, constraint) for every constraint shipped."""
    for path in _ALL_FILES:
        data = _load(path)
        for req in _requirements(data):
            checks = _req_checks(req)
            for c in _req_constraints(req):
                yield pathlib.Path(path).name, _req_id(req), checks, c


_ALL_CONSTRAINTS = list(_iter_constraints())


def test_there_are_constraints_to_validate():
    # Guards against the iteration silently finding nothing (e.g. path change).
    assert len(_ALL_CONSTRAINTS) > 100


@pytest.mark.parametrize(
    "fname,req_id,checks,constraint",
    _ALL_CONSTRAINTS,
    ids=[f"{f}:{r}:{c['Check']}" for f, r, _, c in _ALL_CONSTRAINTS],
)
class Test_Constraint_Wellformed:
    def test_has_required_keys(self, fname, req_id, checks, constraint):
        assert set(constraint) == {
            "Check",
            "ConfigKey",
            "Operator",
            "Value",
        }, f"{fname}:{req_id} malformed constraint {constraint}"

    def test_operator_valid(self, fname, req_id, checks, constraint):
        assert constraint["Operator"] in _VALID_OPERATORS

    def test_check_is_mapped_by_requirement(self, fname, req_id, checks, constraint):
        # No orphan constraints: the target check must be one the requirement runs.
        assert constraint["Check"] in checks, (
            f"{fname}:{req_id} constraint targets {constraint['Check']} "
            f"which the requirement does not map"
        )

    def test_value_type_matches_operator(self, fname, req_id, checks, constraint):
        op, val = constraint["Operator"], constraint["Value"]
        if op in ("subset", "superset", "in"):
            assert isinstance(val, list), f"{fname}:{req_id} {op} needs a list value"
        elif op in ("lte", "gte"):
            # Numeric threshold; bool is not a valid threshold even though it is
            # an int subclass.
            assert isinstance(val, (int, float)) and not isinstance(
                val, bool
            ), f"{fname}:{req_id} {op} needs a numeric value, got {val!r}"
        elif op == "eq":
            assert isinstance(
                val, (bool, int, float, str)
            ), f"{fname}:{req_id} eq needs a scalar value"


class Test_Region_Mute_Invariant:
    """Every requirement mapping a region-scoped check must carry the
    ``mute_non_default_regions == false`` constraint for it."""

    def test_region_checks_always_constrained(self):
        gaps = []
        for path in _ALL_FILES:
            data = _load(path)
            for req in _requirements(data):
                checks = _req_checks(req)
                constrained = {
                    c["Check"]
                    for c in _req_constraints(req)
                    if c["ConfigKey"] == "mute_non_default_regions"
                }
                for region_check in checks & _REGION_CHECKS:
                    if region_check not in constrained:
                        gaps.append(
                            f"{pathlib.Path(path).name}:{_req_id(req)}:{region_check}"
                        )
        assert not gaps, f"region-mute constraint missing for: {gaps}"

    def test_region_mute_constraints_use_eq_false(self):
        for fname, req_id, _checks, c in _ALL_CONSTRAINTS:
            if c["ConfigKey"] == "mute_non_default_regions":
                assert (
                    c["Operator"] == "eq" and c["Value"] is False
                ), f"{fname}:{req_id} region-mute must be eq false"


@pytest.mark.parametrize(
    "path", _ALL_FILES, ids=[pathlib.Path(p).name for p in _ALL_FILES]
)
def test_every_framework_parses_with_constraints(path):
    data = _load(path)
    if "Requirements" in data:
        Compliance(**data)
    else:
        ComplianceFramework.parse_obj(data)
