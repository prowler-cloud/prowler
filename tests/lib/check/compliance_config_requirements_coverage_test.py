"""Coverage test for ``ConfigRequirements`` across the shipped compliance JSONs.

Sibling of ``compliance_config_requirements_data_test.py``: that file validates
that the constraints which *exist* are well-formed; this one validates that
constraints are *not missing*.

Invariant (per-framework):
    For every compliance framework, if it maps a configurable check whose
    configuration can *relax the verdict* (i.e. a looser value makes the check
    PASS when the control is not really satisfied), then that framework must
    declare a ``ConfigRequirements`` entry for that check in at least one of its
    requirements. Otherwise a user could loosen the config and the framework
    would silently report the requirement as compliant.

Why a baseline:
    The invariant is currently violated by a large, pre-existing backlog (the
    constraints were originally added mostly to the CIS frameworks). Fixing all
    of them at once is impractical and needs per-control judgement on the right
    threshold value. So the known gaps are frozen in
    ``compliance_config_requirements_coverage_baseline.json`` and this test:
      - FAILS on any *new* gap not in the baseline (regression guard), and
      - FAILS on any baseline entry that is *no longer* a gap (keeps the
        baseline shrinking as gaps are fixed — delete the entry when you add
        the constraint).

    Regenerate the baseline after intentionally changing the set of gaps with:
        python tests/lib/check/compliance_config_requirements_coverage_test.py --update
"""

import ast
import glob
import json
import os
import pathlib

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_COMPLIANCE_DIR = _REPO_ROOT / "prowler" / "compliance"
_SERVICES_GLOB = str(_REPO_ROOT / "prowler" / "providers" / "*" / "services")
_BASELINE_PATH = (
    pathlib.Path(__file__).with_name(
        "compliance_config_requirements_coverage_baseline.json"
    )
)

# Config keys that a check reads but which do NOT relax its verdict, so a
# requirement mapping such a check does not need a ConfigRequirements:
#   - shodan_api_key: only enables the lookup; without it the check produces an
#     informational/no finding, it never turns a FAIL into a PASS.
#   - detect_secrets_plugins / secrets_ignore_patterns: tune the secret-scanning
#     engine, not a security policy threshold.
# Keep this list small and explicit; everything else is treated as verdict-affecting.
_KEYS_NOT_AFFECTING_VERDICT = {
    "shodan_api_key",
    "detect_secrets_plugins",
    "secrets_ignore_patterns",
}

# Config keys whose Pydantic schema bound already pins the value to the default
# in the direction a user would relax it, so the value CANNOT be loosened — a
# ConfigRequirements would be inert (it could never fire). These are exempt from
# the coverage invariant. The value is the relaxation direction ("gte" = a higher
# value is safer, so loosening means going below; "lte" = the opposite).
# ``test_schema_enforced_keys_are_really_pinned`` proves each entry against the
# live schema + config.yaml default, so a schema/default change can't silently
# leave a real gap hidden here.
_KEYS_SCHEMA_ENFORCED = {
    "vm_backup_min_daily_retention_days": "gte",  # schema ge=7 == default 7
    "days_to_expire_threshold": "gte",  # schema ge=7 == default 7
}

_EXEMPT_KEYS = _KEYS_NOT_AFFECTING_VERDICT | set(_KEYS_SCHEMA_ENFORCED)


def _refers_audit_config(base: ast.AST) -> bool:
    """True when ``base`` is an expression referring to a provider audit_config."""
    if isinstance(base, ast.Attribute) and base.attr == "audit_config":
        return True
    if isinstance(base, ast.Name) and base.id == "audit_config":
        return True
    # getattr(<obj>, "audit_config", <default>)
    if (
        isinstance(base, ast.Call)
        and isinstance(base.func, ast.Name)
        and base.func.id == "getattr"
        and len(base.args) >= 2
        and isinstance(base.args[1], ast.Constant)
        and base.args[1].value == "audit_config"
    ):
        return True
    return False


def _config_keys_in_file(path: str) -> set:
    """Return the set of config keys a check entrypoint reads from audit_config."""
    keys: set = set()
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError):
        return keys

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node):  # audit_config.get("key", ...)
            f = node.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "get"
                and _refers_audit_config(f.value)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
            self.generic_visit(node)

        def visit_Subscript(self, node):  # audit_config["key"]
            if _refers_audit_config(node.value) and isinstance(
                node.slice, ast.Constant
            ):
                if isinstance(node.slice.value, str):
                    keys.add(node.slice.value)
            self.generic_visit(node)

    _Visitor().visit(tree)
    return keys


def _check_config_keys() -> dict:
    """Map every check name to the set of audit_config keys it reads."""
    result: dict = {}
    for services_dir in glob.glob(_SERVICES_GLOB):
        for path in glob.glob(os.path.join(services_dir, "**", "*.py"), recursive=True):
            name = os.path.basename(path)[:-3]
            # Only the check entrypoint file (named like its folder) is a check.
            if name != os.path.basename(os.path.dirname(path)):
                continue
            keys = _config_keys_in_file(path)
            if keys:
                result.setdefault(name, set()).update(keys)
    return result


def _requirements(data):
    return data.get("Requirements") or data.get("requirements") or []


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


def compute_current_gaps() -> set:
    """Return the set of ``<framework_file>::<check>`` pairs missing a constraint.

    A pair is a gap when the framework maps a configurable, verdict-affecting
    check but declares no ConfigRequirements for it in any requirement.
    """
    check_keys = _check_config_keys()
    gaps = set()
    for path in sorted(
        glob.glob(str(_COMPLIANCE_DIR / "**" / "*.json"), recursive=True)
    ):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        fname = pathlib.Path(path).name
        reqs = _requirements(data)

        mapped_configurable = set()
        for req in reqs:
            for chk in _req_checks(req):
                keys = check_keys.get(chk)
                if keys and (keys - _EXEMPT_KEYS):
                    mapped_configurable.add(chk)

        constrained = set()
        for req in reqs:
            for c in _req_constraints(req):
                constrained.add(c.get("Check"))

        for chk in mapped_configurable - constrained:
            gaps.add(f"{fname}::{chk}")
    return gaps


def _load_baseline() -> set:
    if not _BASELINE_PATH.exists():
        return set()
    with open(_BASELINE_PATH, encoding="utf-8") as f:
        return set(json.load(f))


def test_no_new_config_requirement_gaps():
    """No configurable, verdict-affecting check may be mapped without a
    ConfigRequirements unless it is an accepted, pre-existing gap."""
    current = compute_current_gaps()
    baseline = _load_baseline()
    new_gaps = sorted(current - baseline)
    assert not new_gaps, (
        "These frameworks map a configurable check whose config relaxes the "
        "verdict but declare no ConfigRequirements for it. Add the constraint, "
        "or (only if the config truly cannot relax the verdict) add its key to "
        f"_KEYS_NOT_AFFECTING_VERDICT:\n  " + "\n  ".join(new_gaps)
    )


def test_baseline_has_no_stale_entries():
    """Every baseline entry must still be a real gap; fix one → remove it here."""
    current = compute_current_gaps()
    baseline = _load_baseline()
    resolved = sorted(baseline - current)
    assert not resolved, (
        "These baseline entries are no longer gaps (a ConfigRequirements now "
        "exists, or the check/mapping was removed). Delete them from "
        f"{_BASELINE_PATH.name}:\n  " + "\n  ".join(resolved)
    )


def _schema_bounds():
    """Map every config key to its (minimum, maximum) across all provider schemas."""
    from prowler.config.schema.registry import SCHEMAS

    bounds = {}
    for model in SCHEMAS.values():
        if model is None:
            continue
        props = model.model_json_schema().get("properties", {})
        for name, prop in props.items():
            mn = mx = None
            for cand in [prop, *prop.get("anyOf", [])]:
                if "minimum" in cand:
                    mn = cand["minimum"]
                if "maximum" in cand:
                    mx = cand["maximum"]
            if name not in bounds:
                bounds[name] = (mn, mx)
    return bounds


def _config_defaults():
    """Map every config key to its default value from config.yaml (first section wins)."""
    import yaml

    cfg_path = _REPO_ROOT / "prowler" / "config" / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    defaults = {}
    for section in cfg.values():
        if isinstance(section, dict):
            for k, v in section.items():
                defaults.setdefault(k, v)
    return defaults


def test_schema_enforced_keys_are_really_pinned():
    """Each _KEYS_SCHEMA_ENFORCED entry must genuinely be non-relaxable: the
    config.yaml default must equal the schema bound in the relaxation direction
    (gte -> minimum, lte -> maximum). This stops the exemption from hiding a real
    gap if a schema or default ever changes."""
    bounds = _schema_bounds()
    defaults = _config_defaults()
    problems = []
    for key, direction in _KEYS_SCHEMA_ENFORCED.items():
        default = defaults.get(key)
        mn, mx = bounds.get(key, (None, None))
        pin = mn if direction == "gte" else mx
        if default is None or pin is None or default != pin:
            problems.append(
                f"{key} (dir={direction}): default={default!r} schema_min={mn!r} "
                f"schema_max={mx!r} — not pinned, exemption unjustified"
            )
    assert not problems, (
        "These keys are exempted as schema-enforced but the schema no longer "
        "pins them to the default (they CAN now be relaxed → real gap). Add a "
        "ConfigRequirements and remove them from _KEYS_SCHEMA_ENFORCED:\n  "
        + "\n  ".join(problems)
    )


if __name__ == "__main__":
    import sys

    if "--update" in sys.argv:
        gaps = sorted(compute_current_gaps())
        with open(_BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(gaps, f, indent=2)
            f.write("\n")
        print(f"Wrote {len(gaps)} baseline entries to {_BASELINE_PATH}")
    else:
        print(f"Current gaps: {len(compute_current_gaps())}")
