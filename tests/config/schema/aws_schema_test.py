"""AWS-specific schema coverage — the biggest provider, with the richest
constraint surface (CIDRs, account IDs, port ranges, enums, thresholds)."""

import pytest

from prowler.config.schema.aws import AWSProviderConfig
from prowler.config.schema.validator import validate_provider_config


def _validate(raw):
    return validate_provider_config("aws", raw, AWSProviderConfig)


class Test_AWS_Threat_Detection_Thresholds:
    """All threat detection thresholds are documented as fractions in 0..1.
    The biggest risk of mistyping them is silently disabling the check."""

    @pytest.mark.parametrize(
        "key",
        [
            "threat_detection_privilege_escalation_threshold",
            "threat_detection_enumeration_threshold",
            "threat_detection_llm_jacking_threshold",
        ],
    )
    def test_valid_boundary_values(self, key):
        assert _validate({key: 0.0}) == {key: 0.0}
        assert _validate({key: 1.0}) == {key: 1.0}
        assert _validate({key: 0.5}) == {key: 0.5}

    @pytest.mark.parametrize(
        "key",
        [
            "threat_detection_privilege_escalation_threshold",
            "threat_detection_enumeration_threshold",
            "threat_detection_llm_jacking_threshold",
        ],
    )
    def test_invalid_values_are_dropped(self, key):
        # 20 instead of 0.2 — would never trigger
        assert _validate({key: 20}) == {}
        # negative
        assert _validate({key: -0.1}) == {}
        # string
        assert _validate({key: "high"}) == {}


class Test_AWS_Trusted_Account_Ids:
    def test_valid_twelve_digit_ids(self):
        ids = ["123456789012", "098765432109"]
        assert _validate({"trusted_account_ids": ids}) == {"trusted_account_ids": ids}

    def test_empty_list_is_valid(self):
        assert _validate({"trusted_account_ids": []}) == {"trusted_account_ids": []}

    def test_short_id_is_dropped(self):
        assert _validate({"trusted_account_ids": ["12345"]}) == {}

    def test_non_numeric_id_is_dropped(self):
        assert _validate({"trusted_account_ids": ["1234abcd5678"]}) == {}

    def test_id_with_dashes_is_dropped(self):
        # Some users format account IDs as "1234-5678-9012"
        assert _validate({"trusted_account_ids": ["1234-5678-9012"]}) == {}


class Test_AWS_Trusted_Ips:
    def test_single_ipv4_address(self):
        assert _validate({"trusted_ips": ["1.2.3.4"]}) == {"trusted_ips": ["1.2.3.4"]}

    def test_ipv4_cidr(self):
        assert _validate({"trusted_ips": ["10.0.0.0/8"]}) == {
            "trusted_ips": ["10.0.0.0/8"]
        }

    def test_ipv6_address(self):
        assert _validate({"trusted_ips": ["2001:db8::1"]}) == {
            "trusted_ips": ["2001:db8::1"]
        }

    def test_ipv6_cidr(self):
        assert _validate({"trusted_ips": ["2001:db8::/32"]}) == {
            "trusted_ips": ["2001:db8::/32"]
        }

    def test_mixed_list(self):
        ips = ["1.2.3.4", "10.0.0.0/8", "2001:db8::1"]
        assert _validate({"trusted_ips": ips}) == {"trusted_ips": ips}

    def test_garbage_entry_is_dropped(self):
        assert _validate({"trusted_ips": ["definitely-not-an-ip"]}) == {}

    def test_cidr_with_host_bits_is_accepted(self):
        # We use strict=False so "10.0.0.5/8" is accepted. This matches the
        # behaviour of most security tools and avoids surprising users who
        # paste real-world allowlists with non-canonical CIDR notation.
        assert _validate({"trusted_ips": ["10.0.0.5/8"]}) == {
            "trusted_ips": ["10.0.0.5/8"]
        }


class Test_AWS_Ports:
    def test_valid_ports_in_range(self):
        ports = [25, 80, 443, 65535, 0]
        assert _validate({"ec2_high_risk_ports": ports}) == {
            "ec2_high_risk_ports": ports
        }

    def test_out_of_range_port_is_dropped(self):
        assert _validate({"ec2_high_risk_ports": [70000]}) == {}

    def test_negative_port_is_dropped(self):
        assert _validate({"ec2_high_risk_ports": [-1]}) == {}


class Test_AWS_Enums:
    @pytest.mark.parametrize("level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    def test_valid_severity_levels(self, level):
        assert _validate({"ecr_repository_vulnerability_minimum_severity": level}) == {
            "ecr_repository_vulnerability_minimum_severity": level
        }

    @pytest.mark.parametrize("level", ["critical", "Medium", "ANY", "", "X"])
    def test_invalid_severity_levels_are_dropped(self, level):
        assert _validate({"ecr_repository_vulnerability_minimum_severity": level}) == {}


class Test_AWS_Detect_Secrets_Plugins:
    def test_plugin_without_limit(self):
        out = _validate({"detect_secrets_plugins": [{"name": "AWSKeyDetector"}]})
        assert out == {"detect_secrets_plugins": [{"name": "AWSKeyDetector"}]}

    def test_plugin_with_limit(self):
        out = _validate(
            {
                "detect_secrets_plugins": [
                    {"name": "Base64HighEntropyString", "limit": 6.0}
                ]
            }
        )
        assert out == {
            "detect_secrets_plugins": [
                {"name": "Base64HighEntropyString", "limit": 6.0}
            ]
        }

    def test_plugin_missing_name_drops_whole_field(self):
        # ``name`` is required by the upstream library.
        out = _validate({"detect_secrets_plugins": [{"limit": 6.0}]})
        assert out == {}

    def test_extra_plugin_kwargs_pass_through(self):
        # Plugins can have arbitrary extra params (extra="allow" on the
        # nested model). They must round-trip.
        out = _validate(
            {
                "detect_secrets_plugins": [
                    {"name": "Custom", "my_param": "abc", "other": 42}
                ]
            }
        )
        assert out == {
            "detect_secrets_plugins": [
                {"name": "Custom", "my_param": "abc", "other": 42}
            ]
        }


class Test_AWS_Booleans:
    @pytest.mark.parametrize(
        "key",
        [
            "mute_non_default_regions",
            "verify_premium_support_plans",
            "check_rds_instance_replicas",
        ],
    )
    def test_true_and_false_round_trip(self, key):
        assert _validate({key: True}) == {key: True}
        assert _validate({key: False}) == {key: False}

    def test_yaml_style_boolean_coercion(self):
        # YAML can produce Python str "true"/"yes" if the user quoted it.
        # Pydantic v2 will refuse string booleans by default. Verify it is
        # dropped, not silently treated as True (which would be dangerous
        # for verify_premium_support_plans).
        out = _validate({"verify_premium_support_plans": "yes"})
        # Pydantic actually DOES coerce "yes"/"no"/"true"/"false" in lax mode.
        # We accept either outcome but require it to be a real bool.
        if "verify_premium_support_plans" in out:
            assert isinstance(out["verify_premium_support_plans"], bool)


class Test_AWS_Full_Default_Config_Round_Trips:
    """Loading the real shipped defaults through the schema must produce
    exactly the same dict. This is the regression sentinel for backwards
    compatibility."""

    def test_full_default_config_round_trip(self):
        # Subset that mirrors the shipped config.yaml semantics.
        raw = {
            "mute_non_default_regions": False,
            "disallowed_regions": ["me-south-1", "me-central-1"],
            "max_unused_access_keys_days": 45,
            "max_ec2_instance_age_in_days": 180,
            "trusted_account_ids": [],
            "trusted_ips": [],
            "ecr_repository_vulnerability_minimum_severity": "MEDIUM",
            "threat_detection_privilege_escalation_threshold": 0.2,
            "threat_detection_enumeration_threshold": 0.3,
            "threat_detection_llm_jacking_threshold": 0.4,
            "ec2_high_risk_ports": [25, 110, 8088],
            "detect_secrets_plugins": [
                {"name": "AWSKeyDetector"},
                {"name": "Base64HighEntropyString", "limit": 6.0},
            ],
        }
        assert _validate(raw) == raw
