"""Validation coverage for the ConfigRequirements schema.

``Compliance_Requirement_ConfigConstraint`` is the model behind every
``ConfigRequirements`` entry in the compliance framework JSONs. These tests pin
the operator vocabulary, the value-typing rules (notably that booleans are not
coerced to integers), and that constraints survive the legacy → universal
adaptation used by the App backend and the OCSF/table outputs.
"""

import json
import pathlib

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.compliance_models import (
    Compliance,
    Compliance_Requirement_ConfigConstraint,
    adapt_legacy_to_universal,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_CIS_6_0 = _REPO_ROOT / "prowler" / "compliance" / "aws" / "cis_6.0_aws.json"


def _load_cis():
    """Load the CIS 6.0 AWS framework JSON via a context manager."""
    with open(_CIS_6_0, encoding="utf-8") as f:
        return json.load(f)


class Test_Compliance_Requirement_ConfigConstraint:
    @pytest.mark.parametrize(
        "operator,value",
        [
            ("lte", 45),
            ("gte", 365),
            ("eq", False),
            ("in", [1, 2, 3]),
            ("subset", ["1.2", "1.3"]),
            ("superset", ["RSA-1024", "P-192"]),
        ],
    )
    def test_valid_operators(self, operator, value):
        c = Compliance_Requirement_ConfigConstraint(
            Check="some_check", ConfigKey="some_key", Operator=operator, Value=value
        )
        assert c.Operator == operator
        assert c.Value == value

    def test_invalid_operator_rejected(self):
        with pytest.raises(ValidationError):
            Compliance_Requirement_ConfigConstraint(
                Check="c", ConfigKey="k", Operator="between", Value=1
            )

    @pytest.mark.parametrize(
        "operator,value",
        [
            # numeric operators reject non-numeric / boolean values
            ("gte", [1, 2]),
            ("lte", ["45"]),
            ("gte", True),
            # set/list operators reject scalars
            ("subset", 5),
            ("superset", "x"),
            ("in", 1),
            # eq rejects lists
            ("eq", [1, 2]),
        ],
    )
    def test_value_type_inconsistent_with_operator_rejected(self, operator, value):
        # A mistyped Value would otherwise be silently treated as "not satisfied"
        # at runtime, forcing a spurious [CONFIG NOT VALID] FAIL.
        with pytest.raises(ValidationError):
            Compliance_Requirement_ConfigConstraint(
                Check="c", ConfigKey="k", Operator=operator, Value=value
            )

    def test_boolean_value_not_coerced_to_int(self):
        # ``mute_non_default_regions == false`` must stay a bool, not become 0.
        c = Compliance_Requirement_ConfigConstraint(
            Check="securityhub_enabled",
            ConfigKey="mute_non_default_regions",
            Operator="eq",
            Value=False,
        )
        assert c.Value is False
        assert isinstance(c.Value, bool)

    def test_list_value_preserved_for_set_operators(self):
        c = Compliance_Requirement_ConfigConstraint(
            Check="c", ConfigKey="k", Operator="subset", Value=["1.2", "1.3"]
        )
        assert isinstance(c.Value, list)
        assert c.Value == ["1.2", "1.3"]

    def test_missing_required_fields_rejected(self):
        with pytest.raises(ValidationError):
            Compliance_Requirement_ConfigConstraint(Check="c", ConfigKey="k")

    def test_provider_defaults_to_none(self):
        # Single-provider frameworks omit Provider; it is optional.
        c = Compliance_Requirement_ConfigConstraint(
            Check="c", ConfigKey="k", Operator="eq", Value=False
        )
        assert c.Provider is None

    def test_provider_scopes_constraint(self):
        # Universal frameworks tag each constraint with the provider it applies to.
        c = Compliance_Requirement_ConfigConstraint(
            Check="securityhub_enabled",
            Provider="aws",
            ConfigKey="mute_non_default_regions",
            Operator="eq",
            Value=False,
        )
        assert c.Provider == "aws"


class Test_ConfigRequirements_On_Compliance:
    def test_requirements_without_constraints_default_to_none(self):
        compliance = Compliance(**_load_cis())
        # Requirement without configurable checks → ConfigRequirements is None.
        no_constraint = [r for r in compliance.Requirements if not r.ConfigRequirements]
        assert no_constraint
        assert no_constraint[0].ConfigRequirements is None

    def test_requirement_with_constraints_parses(self):
        compliance = Compliance(**_load_cis())
        with_constraint = [r for r in compliance.Requirements if r.ConfigRequirements]
        assert with_constraint, "cis_6.0_aws should declare ConfigRequirements"
        constraint = with_constraint[0].ConfigRequirements[0]
        assert isinstance(constraint, Compliance_Requirement_ConfigConstraint)
        assert constraint.Check
        assert constraint.Operator in {"lte", "gte", "eq", "in", "subset", "superset"}


class Test_Adapt_Legacy_To_Universal:
    def test_config_requirements_carried_to_universal(self):
        legacy = Compliance(**_load_cis())
        universal = adapt_legacy_to_universal(legacy)

        legacy_with = {r.Id for r in legacy.Requirements if r.ConfigRequirements}
        universal_with = {r.id for r in universal.requirements if r.config_requirements}
        assert legacy_with == universal_with
        assert universal_with, "expected at least one requirement with constraints"

        # The constraint payload survives as the typed constraint model with the
        # same fields (``Provider`` is carried through too, ``None`` for
        # single-provider frameworks like CIS AWS).
        sample = next(r for r in universal.requirements if r.config_requirements)
        entry = sample.config_requirements[0]
        assert isinstance(entry, Compliance_Requirement_ConfigConstraint)
        assert set(entry.dict()) == {
            "Check",
            "Provider",
            "ConfigKey",
            "Operator",
            "Value",
        }
        assert entry.Provider is None

    def test_requirements_without_constraints_are_none_in_universal(self):
        legacy = Compliance(**_load_cis())
        universal = adapt_legacy_to_universal(legacy)
        without = [r for r in universal.requirements if not r.config_requirements]
        assert without
        assert without[0].config_requirements is None
