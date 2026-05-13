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


class Test_Vercel_Schema:
    def test_owner_percentage_in_range(self):
        assert _validate("vercel", {"max_owner_percentage": 20}) == {
            "max_owner_percentage": 20
        }
        assert _validate("vercel", {"max_owner_percentage": 0}) == {
            "max_owner_percentage": 0
        }
        assert _validate("vercel", {"max_owner_percentage": 100}) == {
            "max_owner_percentage": 100
        }

    def test_owner_percentage_over_100_dropped(self):
        assert _validate("vercel", {"max_owner_percentage": 150}) == {}

    def test_owner_percentage_negative_dropped(self):
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
