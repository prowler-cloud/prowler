"""End-to-end coverage: every shipped framework that declares ``ConfigRequirements``
must apply the config-status override through the *real* table dispatcher.

The companion ``config_status_renderer_coverage_test`` proves no renderer file
ignores the override. This test closes the other half of the gap that let
``okta_idaas_stig`` ship ConfigRequirements its renderers never applied: it walks
every per-provider compliance JSON that declares constraints, routes a synthetic
PASS finding through ``display_compliance_table`` exactly as a scan would, and
asserts the requirement is forced to FAIL when the scan's config is too loose.

It runs each framework twice — once with a config that *violates* the first
constraint and once with a config that *satisfies* it — and asserts the violating
run reports strictly more failures. Comparing the two runs is language-neutral
(only the parenthesised counts are read, never the localized PASS/FAIL labels) and
self-checking (a renderer that ignored the override would report equal counts).

Universal (multi-provider) frameworks render through a different path and are
covered by ``universal/universal_table_config_requirements_test.py``.
"""

import glob
import io
import json
import pathlib
import re
import tempfile
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance import display_compliance_table

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
_COMPLIANCE_DIR = _REPO_ROOT / "prowler" / "compliance"

# Per-provider JSONs live in a provider subdir; top-level files are universal.
_PROVIDER_JSONS = sorted(glob.glob(str(_COMPLIANCE_DIR / "*" / "*.json")))


def _first_constraint(data):
    """Return ``(check, config_key, operator, value)`` of the first declared
    constraint, or ``None`` when the framework declares none."""
    for requirement in data.get("Requirements", []):
        constraints = requirement.get("ConfigRequirements")
        if constraints:
            c = constraints[0]
            return c["Check"], c["ConfigKey"], c["Operator"], c["Value"]
    return None


def _violating_value(operator, value):
    """A config value that breaks the constraint (forces the requirement FAIL)."""
    if operator == "lte":
        return value + 1
    if operator == "gte":
        return value - 1
    if operator == "eq":
        if isinstance(value, bool):
            return not value
        if isinstance(value, (int, float)):
            return value + 1
        return f"{value}__violates__"
    if operator == "in":
        return "__not_in_allowed_set__"
    if operator == "subset":
        return list(value) + ["__extra_not_allowed__"]
    if operator == "superset":
        return []
    raise AssertionError(f"unhandled operator {operator}")


def _satisfying_value(operator, value):
    """A config value that satisfies the constraint (requirement keeps its status)."""
    if operator in ("lte", "gte", "eq"):
        return value
    if operator == "in":
        return value[0]
    if operator == "subset":
        return list(value)
    if operator == "superset":
        return list(value)
    raise AssertionError(f"unhandled operator {operator}")


def _fail_count(findings, bulk, name, provider, applied_config):
    """Render the framework table with ``applied_config`` and return the FAIL
    count from the overview, or ``None`` when the table renders nothing."""

    def _not_implemented(*_a, **_k):
        raise NotImplementedError

    fake_provider = SimpleNamespace(
        audit_config=applied_config,
        type=provider,
        display_compliance_table=_not_implemented,
    )
    buffer = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=fake_provider,
        ):
            with redirect_stdout(buffer):
                display_compliance_table(findings, bulk, name, "output", tmp, False)
    plain = re.sub(r"\x1b\[[0-9;]*m", "", buffer.getvalue())
    # The overview's first parenthesised count is always the FAIL tally, in
    # every renderer and every locale (only the label is translated).
    counts = re.findall(r"\(\s*(\d+)\s*\)", plain)
    return int(counts[0]) if counts else None


def _frameworks_with_constraints():
    for path in _PROVIDER_JSONS:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if _first_constraint(data):
            name = pathlib.Path(path).stem
            yield pytest.param(path, data, id=name)


@pytest.mark.parametrize("path, data", list(_frameworks_with_constraints()))
def test_framework_constraints_force_fail_through_dispatcher(path, data):
    provider = pathlib.Path(path).parent.name
    name = pathlib.Path(path).stem
    check, config_key, operator, value = _first_constraint(data)
    compliance = Compliance(**data)

    def _finding():
        return SimpleNamespace(
            check_metadata=SimpleNamespace(CheckID=check),
            check_id=check,
            status="PASS",
            muted=False,
        )

    # Two findings: the renderers only print the table when more than one
    # finding maps to the framework.
    findings = [_finding(), _finding()]
    bulk = {check: SimpleNamespace(Compliance=[compliance])}

    strict = _fail_count(
        findings, bulk, name, provider, {config_key: _satisfying_value(operator, value)}
    )
    loose = _fail_count(
        findings, bulk, name, provider, {config_key: _violating_value(operator, value)}
    )

    if strict is None and loose is None:
        # The framework's renderer gates rendering on its name/version and does
        # not paint a table for this framework id. There is no status to assert
        # here; the renderer itself is still proven config-aware by
        # config_status_renderer_coverage_test. Surfaced rather than silently
        # passed so the skip is visible.
        pytest.skip(f"{name}: renderer paints no table for this framework id")

    assert strict == 0, (
        f"{name}: PASS findings reported {strict} failures with a compliant "
        "config; the control run should be clean."
    )
    assert loose and loose > 0, (
        f"{name}: a PASS finding whose requirement maps {check} ran with "
        f"{config_key} too loose for the constraint ({operator} {value}) was NOT "
        "forced to FAIL. The framework declares ConfigRequirements its renderer "
        "fails to apply — wire it through the config-status helpers."
    )
