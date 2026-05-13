"""Behavioural tests for ``validate_provider_config``.

The validator is the gatekeeper for every provider schema: its job is to
keep backwards-compatible behaviour (no exceptions, drop only the bad
keys) while loudly logging type mistakes.
"""

import logging

import pytest

from prowler.config.schema.aws import AWSProviderConfig
from prowler.config.schema.registry import SCHEMAS
from prowler.config.schema.validator import validate_provider_config


class Test_Validate_Provider_Config_Contract:
    """Generic invariants that must hold for any schema."""

    def test_returns_empty_dict_when_raw_is_not_a_dict(self):
        assert validate_provider_config("aws", None, AWSProviderConfig) == {}
        assert validate_provider_config("aws", "string", AWSProviderConfig) == {}
        assert validate_provider_config("aws", 42, AWSProviderConfig) == {}
        assert validate_provider_config("aws", [], AWSProviderConfig) == {}

    def test_returns_raw_unchanged_when_no_schema_registered(self):
        raw = {"anything": "goes", "even": [1, 2, 3]}
        assert validate_provider_config("mystery_provider", raw, None) == raw

    def test_unknown_keys_pass_through_for_plugin_compatibility(self):
        # Third-party plugins inject arbitrary keys; the schema must NOT
        # filter them. This is the contract that lets the plugin ecosystem
        # keep working when we add validation.
        raw = {"plugin_custom_key": "foo", "lambda_min_azs": 2}
        assert validate_provider_config("aws", raw, AWSProviderConfig) == {
            "plugin_custom_key": "foo",
            "lambda_min_azs": 2,
        }

    def test_empty_dict_returns_empty_dict(self):
        assert validate_provider_config("aws", {}, AWSProviderConfig) == {}

    def test_known_valid_value_passes_through_unchanged(self):
        raw = {"max_ec2_instance_age_in_days": 180}
        assert validate_provider_config("aws", raw, AWSProviderConfig) == {
            "max_ec2_instance_age_in_days": 180
        }


class Test_Validate_Provider_Config_Coercion:
    """Pydantic v2 coerces common type-mistakes automatically. We want to
    keep that behaviour so quoted numerics in user configs ``Just Work``."""

    def test_string_numeric_is_coerced_to_int(self):
        out = validate_provider_config(
            "aws", {"max_ec2_instance_age_in_days": "180"}, AWSProviderConfig
        )
        assert out == {"max_ec2_instance_age_in_days": 180}
        assert isinstance(out["max_ec2_instance_age_in_days"], int)

    def test_string_numeric_is_coerced_to_float(self):
        out = validate_provider_config(
            "aws",
            {"threat_detection_privilege_escalation_threshold": "0.4"},
            AWSProviderConfig,
        )
        assert out == {"threat_detection_privilege_escalation_threshold": 0.4}


class Test_Validate_Provider_Config_Drops_Invalid_Keys:
    """When a field fails validation, only that key is dropped from the
    returned dict. The rest of the user's config is preserved so the
    consumer's ``audit_config.get(key, default)`` falls back to its own
    built-in default for the offending field and uses user values for
    everything else."""

    def test_out_of_range_threshold_is_dropped(self, caplog):
        with caplog.at_level(logging.WARNING):
            out = validate_provider_config(
                "aws",
                {
                    "threat_detection_privilege_escalation_threshold": 2.0,
                    "lambda_min_azs": 2,
                },
                AWSProviderConfig,
            )
        assert out == {"lambda_min_azs": 2}
        assert any(
            "threat_detection_privilege_escalation_threshold" in r.getMessage()
            for r in caplog.records
        )

    def test_invalid_enum_is_dropped(self):
        out = validate_provider_config(
            "aws",
            {"ecr_repository_vulnerability_minimum_severity": "medum"},
            AWSProviderConfig,
        )
        assert out == {}

    def test_wrong_shape_list_as_string_is_dropped(self):
        # Classic YAML mistake: ``disallowed_regions: me-south-1`` without dashes.
        # Pydantic refuses to silently treat a str as a single-element list,
        # which is exactly the safety guarantee we want.
        out = validate_provider_config(
            "aws",
            {"disallowed_regions": "me-south-1", "lambda_min_azs": 2},
            AWSProviderConfig,
        )
        assert out == {"lambda_min_azs": 2}

    def test_negative_positive_int_is_dropped(self):
        out = validate_provider_config(
            "aws", {"max_ec2_instance_age_in_days": -1}, AWSProviderConfig
        )
        assert out == {}

    def test_zero_is_dropped_for_strictly_positive_field(self):
        # max_ec2_instance_age_in_days is gt=0. Zero would silently cause every
        # instance to FAIL the age check.
        out = validate_provider_config(
            "aws", {"max_ec2_instance_age_in_days": 0}, AWSProviderConfig
        )
        assert out == {}

    def test_multiple_invalid_keys_yield_multiple_warnings(self, caplog):
        with caplog.at_level(logging.WARNING):
            out = validate_provider_config(
                "aws",
                {
                    "max_ec2_instance_age_in_days": "nope",
                    "ecr_repository_vulnerability_minimum_severity": "medum",
                    "valid_extra_key": "kept",
                },
                AWSProviderConfig,
            )
        assert out == {"valid_extra_key": "kept"}
        messages = " ".join(r.getMessage() for r in caplog.records)
        assert "max_ec2_instance_age_in_days" in messages
        assert "ecr_repository_vulnerability_minimum_severity" in messages

    def test_warning_message_includes_provider_and_field(self, caplog):
        with caplog.at_level(logging.WARNING):
            validate_provider_config(
                "aws",
                {"threat_detection_privilege_escalation_threshold": 5.0},
                AWSProviderConfig,
            )
        assert any(
            "prowler.config[aws.threat_detection_privilege_escalation_threshold]"
            in r.getMessage()
            for r in caplog.records
        )


class Test_Schemas_Registry:
    """Every provider mentioned in the YAML config must have a schema."""

    @pytest.mark.parametrize(
        "provider",
        [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "mongodbatlas",
            "cloudflare",
            "vercel",
        ],
    )
    def test_schema_registered_for_provider(self, provider):
        assert provider in SCHEMAS
        assert SCHEMAS[provider] is not None
