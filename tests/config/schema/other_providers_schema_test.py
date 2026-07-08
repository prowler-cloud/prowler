"""Smaller-provider schema coverage. One happy path + one invalid path
per field is enough to lock in the contract; the validator behaviour
itself is covered exhaustively in validator_test.py."""

import pytest

from prowler.config.schema.registry import SCHEMAS
from prowler.config.schema.validator import validate_provider_config


def _validate(provider, raw):
    return validate_provider_config(provider, raw, SCHEMAS[provider])


class Test_Azure_Schema:
    @pytest.mark.parametrize("level", ["Low", "Medium", "High", "Critical"])
    def test_defender_risk_level_valid_values(self, level):
        assert _validate(
            "azure", {"defender_attack_path_minimal_risk_level": level}
        ) == {"defender_attack_path_minimal_risk_level": level}

    def test_defender_risk_level_lowercase_dropped(self):
        # Case matters: the matching check uses Title-case comparison.
        assert (
            _validate("azure", {"defender_attack_path_minimal_risk_level": "high"})
            == {}
        )

    def test_apim_threshold_in_range(self):
        out = _validate("azure", {"apim_threat_detection_llm_jacking_threshold": 0.1})
        assert out == {"apim_threat_detection_llm_jacking_threshold": 0.1}

    def test_apim_threshold_out_of_range(self):
        out = _validate("azure", {"apim_threat_detection_llm_jacking_threshold": 1.5})
        assert out == {}

    def test_vm_backup_retention_must_be_positive(self):
        assert _validate("azure", {"vm_backup_min_daily_retention_days": 7}) == {
            "vm_backup_min_daily_retention_days": 7
        }
        assert _validate("azure", {"vm_backup_min_daily_retention_days": 0}) == {}
        assert _validate("azure", {"vm_backup_min_daily_retention_days": -1}) == {}


class Test_GCP_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "mig_min_zones": 2,
            "max_snapshot_age_days": 90,
            "max_unused_account_days": 180,
            "storage_min_retention_days": 90,
        }
        assert _validate("gcp", raw) == raw

    def test_zero_zone_count_dropped(self):
        assert _validate("gcp", {"mig_min_zones": 0}) == {}


class Test_Kubernetes_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "audit_log_maxbackup": 10,
            "audit_log_maxsize": 100,
            "audit_log_maxage": 30,
        }
        assert _validate("kubernetes", raw) == raw

    def test_negative_audit_log_dropped(self):
        assert _validate("kubernetes", {"audit_log_maxage": -1}) == {}


class Test_M365_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "sign_in_frequency": 4,
            "recommended_mailtips_large_audience_threshold": 25,
            "audit_log_age": 90,
        }
        assert _validate("m365", raw) == raw

    def test_negative_audit_log_age_dropped(self):
        assert _validate("m365", {"audit_log_age": -10}) == {}


class Test_GitHub_Schema:
    def test_valid_threshold(self):
        assert _validate("github", {"inactive_not_archived_days_threshold": 180}) == {
            "inactive_not_archived_days_threshold": 180
        }

    def test_zero_threshold_dropped(self):
        assert _validate("github", {"inactive_not_archived_days_threshold": 0}) == {}


class Test_MongoDBAtlas_Schema:
    def test_valid(self):
        assert _validate(
            "mongodbatlas", {"max_service_account_secret_validity_hours": 8}
        ) == {"max_service_account_secret_validity_hours": 8}

    def test_invalid_negative(self):
        assert (
            _validate("mongodbatlas", {"max_service_account_secret_validity_hours": -1})
            == {}
        )


class Test_Cloudflare_Schema:
    def test_zero_retries_allowed(self):
        # 0 is explicitly documented as "disable retries" in config.yaml.
        assert _validate("cloudflare", {"max_retries": 0}) == {"max_retries": 0}

    def test_positive_retries_allowed(self):
        assert _validate("cloudflare", {"max_retries": 3}) == {"max_retries": 3}

    def test_negative_retries_dropped(self):
        assert _validate("cloudflare", {"max_retries": -1}) == {}


class Test_Okta_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "okta_max_session_idle_minutes": 15,
            "okta_max_session_lifetime_minutes": 18 * 60,
            "okta_admin_console_idle_timeout_max_minutes": 15,
            "okta_user_inactivity_max_days": 35,
            "okta_dod_approved_ca_issuer_patterns": [r"\bOU=DoD\b", r"\bOU=ECA\b"],
        }
        assert _validate("okta", raw) == raw

    def test_zero_idle_minutes_dropped(self):
        assert _validate("okta", {"okta_max_session_idle_minutes": 0}) == {}

    def test_negative_inactivity_days_dropped(self):
        assert _validate("okta", {"okta_user_inactivity_max_days": -1}) == {}

    def test_full_rate_limit_config_round_trip(self):
        raw = {
            "okta_requests_per_second": 4.0,
            "okta_max_retries": 5,
            "okta_request_timeout": 300,
        }
        assert _validate("okta", raw) == raw

    def test_requests_per_second_zero_allowed(self):
        # 0 is documented as "disable throttling" in config.yaml.
        assert _validate("okta", {"okta_requests_per_second": 0}) == {
            "okta_requests_per_second": 0
        }

    def test_requests_per_second_sub_one_allowed(self):
        assert _validate("okta", {"okta_requests_per_second": 0.5}) == {
            "okta_requests_per_second": 0.5
        }

    def test_requests_per_second_floor_allowed(self):
        # 0.1 is the lowest non-zero rate accepted.
        assert _validate("okta", {"okta_requests_per_second": 0.1}) == {
            "okta_requests_per_second": 0.1
        }

    def test_requests_per_second_below_floor_dropped(self):
        # A tiny rate (e.g. 0.001 -> ~1000s/request) would make scans take
        # days or years; it must be rejected, not silently honoured.
        assert _validate("okta", {"okta_requests_per_second": 0.001}) == {}
        assert _validate("okta", {"okta_requests_per_second": 0.05}) == {}

    def test_requests_per_second_above_max_dropped(self):
        assert _validate("okta", {"okta_requests_per_second": 101}) == {}

    def test_requests_per_second_negative_dropped(self):
        assert _validate("okta", {"okta_requests_per_second": -1}) == {}

    def test_max_retries_zero_allowed(self):
        assert _validate("okta", {"okta_max_retries": 0}) == {"okta_max_retries": 0}

    def test_max_retries_out_of_range_dropped(self):
        assert _validate("okta", {"okta_max_retries": -1}) == {}
        assert _validate("okta", {"okta_max_retries": 11}) == {}

    def test_request_timeout_zero_allowed(self):
        # 0 is documented as "disable the timeout" in config.yaml.
        assert _validate("okta", {"okta_request_timeout": 0}) == {
            "okta_request_timeout": 0
        }

    def test_request_timeout_in_range_allowed(self):
        assert _validate("okta", {"okta_request_timeout": 300}) == {
            "okta_request_timeout": 300
        }

    def test_request_timeout_out_of_range_dropped(self):
        assert _validate("okta", {"okta_request_timeout": -1}) == {}
        assert _validate("okta", {"okta_request_timeout": 3601}) == {}

    def test_non_numeric_value_dropped(self):
        # A typo'd string must not flow through to the limiter (it would crash
        # the `> 0` comparison during provider init).
        assert _validate("okta", {"okta_requests_per_second": "fast"}) == {}


class Test_Vercel_Schema:
    def test_owner_percentage_in_range(self):
        assert _validate("vercel", {"max_owner_percentage": 20}) == {
            "max_owner_percentage": 20
        }
        assert _validate("vercel", {"max_owner_percentage": 1}) == {
            "max_owner_percentage": 1
        }
        assert _validate("vercel", {"max_owner_percentage": 50}) == {
            "max_owner_percentage": 50
        }

    def test_owner_percentage_over_max_dropped(self):
        # Tightened to 1..50 — anything above (incl. previous 100) is dropped.
        assert _validate("vercel", {"max_owner_percentage": 51}) == {}
        assert _validate("vercel", {"max_owner_percentage": 150}) == {}

    def test_owner_percentage_zero_or_negative_dropped(self):
        # 0 is no longer a valid configuration (defeats PoLP signal).
        assert _validate("vercel", {"max_owner_percentage": 0}) == {}
        assert _validate("vercel", {"max_owner_percentage": -1}) == {}

    def test_full_default_config_round_trip(self):
        raw = {
            "stable_branches": ["main", "master"],
            "days_to_expire_threshold": 7,
            "stale_token_threshold_days": 90,
            "stale_invitation_threshold_days": 30,
            "max_owner_percentage": 20,
            "max_owners": 3,
            "secret_suffixes": ["_KEY", "_SECRET", "_TOKEN"],
        }
        assert _validate("vercel", raw) == raw


class Test_AlibabaCloud_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "max_cluster_check_days": 7,
            "max_console_access_days": 90,
            "min_log_retention_days": 365,
            "min_rds_audit_retention_days": 180,
        }
        assert _validate("alibabacloud", raw) == raw

    def test_zero_cluster_check_days_dropped(self):
        assert _validate("alibabacloud", {"max_cluster_check_days": 0}) == {}

    def test_console_access_below_min_dropped(self):
        # 30 is the documented floor; anything below produces false positives.
        assert _validate("alibabacloud", {"max_console_access_days": 29}) == {}


class Test_OpenStack_Schema:
    def test_valid_values_round_trip(self):
        raw = {
            "image_sharing_threshold": 5,
            "secrets_ignore_patterns": ["AKIA[0-9A-Z]{16}"],
        }
        assert _validate("openstack", raw) == raw

    def test_zero_threshold_dropped(self):
        assert _validate("openstack", {"image_sharing_threshold": 0}) == {}


class Test_E2ENetworks_Schema:
    def test_valid_values_round_trip(self):
        raw = {"require_bitninja_on_load_balancers": True}
        assert _validate("e2enetworks", raw) == raw

    def test_non_bool_value_dropped(self):
        assert (
            _validate("e2enetworks", {"require_bitninja_on_load_balancers": "maybe"})
            == {}
        )
