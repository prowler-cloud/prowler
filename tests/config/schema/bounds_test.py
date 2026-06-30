"""Boundary tests for the safety bounds added on top of the upstream schemas.

Each parametrised case checks (a) the min and max values are accepted and
(b) one step outside the range is rejected. Custom validators (semver,
EKS minor, dotted version, port range, account IDs, IPs) get focused
positive/negative tests.

Tests use the public adapter ``prowler.config.scan_config_schema``: a
schema violation surfaces as a list of ``{"path", "message"}`` entries.
This keeps the contract the Prowler App backend depends on under test.
"""

import pytest

from prowler.config.scan_config_schema import validate_scan_config


def _has_error_for(errors: list[dict], path_substr: str) -> bool:
    return any(path_substr in e["path"] for e in errors)


# Each tuple: (provider, key, min_allowed, max_allowed)
INT_BOUND_CASES = [
    # AWS
    ("aws", "max_unused_access_keys_days", 30, 180),
    ("aws", "max_console_access_days", 30, 180),
    ("aws", "max_unused_sagemaker_access_days", 7, 180),
    ("aws", "max_security_group_rules", 1, 1000),
    ("aws", "max_ec2_instance_age_in_days", 1, 1095),
    ("aws", "recommended_cdk_bootstrap_version", 1, 100),
    ("aws", "max_idle_disconnect_timeout_in_seconds", 60, 1800),
    ("aws", "max_disconnect_timeout_in_seconds", 60, 3600),
    ("aws", "max_session_duration_seconds", 600, 86400),
    ("aws", "lambda_min_azs", 1, 6),
    ("aws", "threat_detection_privilege_escalation_minutes", 5, 43200),
    ("aws", "threat_detection_enumeration_minutes", 5, 43200),
    ("aws", "threat_detection_llm_jacking_minutes", 5, 43200),
    ("aws", "days_to_expire_threshold", 7, 365),
    ("aws", "elb_min_azs", 1, 6),
    ("aws", "elbv2_min_azs", 1, 6),
    ("aws", "minimum_snapshot_retention_period", 1, 35),
    ("aws", "max_days_secret_unused", 7, 365),
    ("aws", "max_days_secret_unrotated", 1, 180),
    ("aws", "min_kinesis_stream_retention_hours", 24, 8760),
    # Azure
    ("azure", "vm_backup_min_daily_retention_days", 7, 9999),
    ("azure", "apim_threat_detection_llm_jacking_minutes", 5, 43200),
    # GCP
    ("gcp", "mig_min_zones", 1, 5),
    ("gcp", "max_snapshot_age_days", 1, 1095),
    ("gcp", "max_unused_account_days", 30, 365),
    ("gcp", "storage_min_retention_days", 1, 3650),
    # Kubernetes
    ("kubernetes", "audit_log_maxbackup", 2, 1000),
    ("kubernetes", "audit_log_maxsize", 10, 10000),
    ("kubernetes", "audit_log_maxage", 7, 3650),
    # M365
    ("m365", "sign_in_frequency", 1, 168),
    ("m365", "recommended_mailtips_large_audience_threshold", 5, 10000),
    ("m365", "audit_log_age", 30, 3650),
    # GitHub
    ("github", "inactive_not_archived_days_threshold", 30, 3650),
    # MongoDB Atlas
    ("mongodbatlas", "max_service_account_secret_validity_hours", 1, 720),
    # Cloudflare
    ("cloudflare", "max_retries", 0, 10),
    # Vercel
    ("vercel", "days_to_expire_threshold", 7, 365),
    ("vercel", "stale_token_threshold_days", 30, 3650),
    ("vercel", "stale_invitation_threshold_days", 7, 365),
    ("vercel", "max_owner_percentage", 1, 50),
    ("vercel", "max_owners", 1, 1000),
    # Okta
    ("okta", "okta_max_session_idle_minutes", 1, 1440),
    ("okta", "okta_max_session_lifetime_minutes", 1, 43200),
    ("okta", "okta_admin_console_idle_timeout_max_minutes", 1, 1440),
    ("okta", "okta_user_inactivity_max_days", 1, 3650),
    # Alibaba Cloud
    ("alibabacloud", "max_cluster_check_days", 1, 365),
    ("alibabacloud", "max_console_access_days", 30, 180),
    ("alibabacloud", "min_log_retention_days", 1, 3650),
    ("alibabacloud", "min_rds_audit_retention_days", 1, 3650),
    # OpenStack
    ("openstack", "image_sharing_threshold", 1, 1000),
]


FLOAT_THRESHOLD_FIELDS = [
    ("aws", "threat_detection_privilege_escalation_threshold"),
    ("aws", "threat_detection_enumeration_threshold"),
    ("aws", "threat_detection_llm_jacking_threshold"),
    ("azure", "apim_threat_detection_llm_jacking_threshold"),
]


class TestIntegerBounds:
    """Each int field accepts both ends of its range and rejects ±1 outside."""

    @pytest.mark.parametrize("provider, key, lo, hi", INT_BOUND_CASES)
    def test_min_accepted(self, provider, key, lo, hi):
        assert validate_scan_config({provider: {key: lo}}) == []

    @pytest.mark.parametrize("provider, key, lo, hi", INT_BOUND_CASES)
    def test_max_accepted(self, provider, key, lo, hi):
        assert validate_scan_config({provider: {key: hi}}) == []

    @pytest.mark.parametrize("provider, key, lo, hi", INT_BOUND_CASES)
    def test_below_min_rejected(self, provider, key, lo, hi):
        errors = validate_scan_config({provider: {key: lo - 1}})
        assert _has_error_for(errors, f"{provider}.{key}"), errors

    @pytest.mark.parametrize("provider, key, lo, hi", INT_BOUND_CASES)
    def test_above_max_rejected(self, provider, key, lo, hi):
        errors = validate_scan_config({provider: {key: hi + 1}})
        assert _has_error_for(errors, f"{provider}.{key}"), errors


class TestFloatThresholds:
    """Threshold floats must stay within 0..1 inclusive."""

    @pytest.mark.parametrize("provider, key", FLOAT_THRESHOLD_FIELDS)
    def test_zero_and_one_accepted(self, provider, key):
        assert validate_scan_config({provider: {key: 0.0}}) == []
        assert validate_scan_config({provider: {key: 1.0}}) == []
        assert validate_scan_config({provider: {key: 0.5}}) == []

    @pytest.mark.parametrize("provider, key", FLOAT_THRESHOLD_FIELDS)
    def test_negative_rejected(self, provider, key):
        errors = validate_scan_config({provider: {key: -0.01}})
        assert _has_error_for(errors, f"{provider}.{key}")

    @pytest.mark.parametrize("provider, key", FLOAT_THRESHOLD_FIELDS)
    def test_above_one_rejected(self, provider, key):
        errors = validate_scan_config({provider: {key: 1.01}})
        assert _has_error_for(errors, f"{provider}.{key}")


class TestCloudWatchRetention:
    """`log_group_retention_days` only accepts the AWS-approved enum values."""

    @pytest.mark.parametrize("value", [1, 7, 30, 365, 731, 3653])
    def test_valid_values_accepted(self, value):
        assert validate_scan_config({"aws": {"log_group_retention_days": value}}) == []

    @pytest.mark.parametrize("value", [0, 2, 42, 500, 999, 4000])
    def test_invalid_values_rejected(self, value):
        errors = validate_scan_config({"aws": {"log_group_retention_days": value}})
        assert _has_error_for(errors, "aws.log_group_retention_days")


class TestSemverValidator:
    """AWS Fargate platform versions: X.Y.Z."""

    @pytest.mark.parametrize("value", ["1.4.0", "1.0.0", "0.0.1", "10.20.30"])
    def test_accepts_semver(self, value):
        assert (
            validate_scan_config({"aws": {"fargate_linux_latest_version": value}}) == []
        )

    @pytest.mark.parametrize("value", ["1.4", "1", "v1.4.0", "1.4.0-beta", "a.b.c", ""])
    def test_rejects_non_semver(self, value):
        errors = validate_scan_config({"aws": {"fargate_linux_latest_version": value}})
        assert _has_error_for(errors, "aws.fargate_linux_latest_version")


class TestEksVersionValidator:
    """`eks_cluster_oldest_version_supported` expects MAJOR.MINOR."""

    @pytest.mark.parametrize("value", ["1.28", "1.29", "1.30", "2.0"])
    def test_accepts_minor(self, value):
        assert (
            validate_scan_config(
                {"aws": {"eks_cluster_oldest_version_supported": value}}
            )
            == []
        )

    @pytest.mark.parametrize("value", ["1.28.0", "v1.28", "1", "1.x", ""])
    def test_rejects_invalid(self, value):
        errors = validate_scan_config(
            {"aws": {"eks_cluster_oldest_version_supported": value}}
        )
        assert _has_error_for(errors, "aws.eks_cluster_oldest_version_supported")


class TestEksLogTypesEnum:
    """Only the documented log types are accepted."""

    def test_full_enum_accepted(self):
        assert (
            validate_scan_config(
                {
                    "aws": {
                        "eks_required_log_types": [
                            "api",
                            "audit",
                            "authenticator",
                            "controllerManager",
                            "scheduler",
                        ]
                    }
                }
            )
            == []
        )

    def test_unknown_type_rejected(self):
        errors = validate_scan_config(
            {"aws": {"eks_required_log_types": ["api", "telemetry"]}}
        )
        assert _has_error_for(errors, "aws.eks_required_log_types")


class TestAzureDottedVersion:
    """App Service versions accept 'X' and 'X.Y' but not 'X.Y.Z' or junk."""

    @pytest.mark.parametrize("value", ["8.2", "3.12", "17"])
    def test_accepts(self, value):
        assert validate_scan_config({"azure": {"php_latest_version": value}}) == []
        assert validate_scan_config({"azure": {"python_latest_version": value}}) == []
        assert validate_scan_config({"azure": {"java_latest_version": value}}) == []

    @pytest.mark.parametrize("value", ["8.2.0", "v8", "8.x", ""])
    def test_rejects(self, value):
        errors = validate_scan_config({"azure": {"php_latest_version": value}})
        assert _has_error_for(errors, "azure.php_latest_version")


class TestAzureTlsLiteralEnum:
    """Only TLS 1.2 and 1.3 are tolerated by the recommended list."""

    def test_accepted_versions(self):
        assert (
            validate_scan_config(
                {"azure": {"recommended_minimal_tls_versions": ["1.2", "1.3"]}}
            )
            == []
        )

    @pytest.mark.parametrize("value", ["1.0", "1.1", "2.0", ""])
    def test_unknown_version_rejected(self, value):
        errors = validate_scan_config(
            {"azure": {"recommended_minimal_tls_versions": [value]}}
        )
        assert _has_error_for(errors, "azure.recommended_minimal_tls_versions")


class TestAzureRiskLevelLiteral:
    """Defender attack-path risk level is a closed enum."""

    @pytest.mark.parametrize("value", ["Low", "Medium", "High", "Critical"])
    def test_accepted(self, value):
        assert (
            validate_scan_config(
                {"azure": {"defender_attack_path_minimal_risk_level": value}}
            )
            == []
        )

    @pytest.mark.parametrize("value", ["low", "CRITICAL", "Severe", ""])
    def test_rejected(self, value):
        errors = validate_scan_config(
            {"azure": {"defender_attack_path_minimal_risk_level": value}}
        )
        assert _has_error_for(errors, "azure.defender_attack_path_minimal_risk_level")


class TestECRSeverityLiteral:
    """ECR severity is a closed enum (with INFORMATIONAL allowed)."""

    @pytest.mark.parametrize(
        "value",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
    )
    def test_accepted(self, value):
        assert (
            validate_scan_config(
                {"aws": {"ecr_repository_vulnerability_minimum_severity": value}}
            )
            == []
        )

    @pytest.mark.parametrize("value", ["URGENT", "low", "Crit", ""])
    def test_rejected(self, value):
        errors = validate_scan_config(
            {"aws": {"ecr_repository_vulnerability_minimum_severity": value}}
        )
        assert _has_error_for(
            errors, "aws.ecr_repository_vulnerability_minimum_severity"
        )


class TestPortRangeValidator:
    """Each entry of `ec2_high_risk_ports` must be 1..65535 (0 is reserved)."""

    def test_valid_ports(self):
        assert (
            validate_scan_config({"aws": {"ec2_high_risk_ports": [1, 22, 8080, 65535]}})
            == []
        )

    @pytest.mark.parametrize("value", [-1, 0, 65536, 99999])
    def test_invalid_port_rejected(self, value):
        errors = validate_scan_config({"aws": {"ec2_high_risk_ports": [80, value]}})
        assert _has_error_for(errors, "aws.ec2_high_risk_ports")


class TestAccountIdsValidator:
    """AWS account IDs are 12-digit strings."""

    def test_valid(self):
        assert (
            validate_scan_config(
                {"aws": {"trusted_account_ids": ["123456789012", "098765432109"]}}
            )
            == []
        )

    @pytest.mark.parametrize(
        "value", ["12345", "12345678901", "1234567890123", "12345678901a"]
    )
    def test_invalid_rejected(self, value):
        errors = validate_scan_config({"aws": {"trusted_account_ids": [value]}})
        assert _has_error_for(errors, "aws.trusted_account_ids")


class TestTrustedIpsValidator:
    """Trusted IPs accept IPv4, IPv6, and CIDR; reject junk."""

    @pytest.mark.parametrize(
        "value",
        ["1.2.3.4", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"],
    )
    def test_valid(self, value):
        assert validate_scan_config({"aws": {"trusted_ips": [value]}}) == []

    @pytest.mark.parametrize(
        "value", ["not.an.ip", "1.2.3.300", "10.0.0.0/40", "::ffff:::"]
    )
    def test_invalid_rejected(self, value):
        errors = validate_scan_config({"aws": {"trusted_ips": [value]}})
        assert _has_error_for(errors, "aws.trusted_ips")


class TestAdapterRobustness:
    """Top-level adapter behaviour the Prowler App backend depends on."""

    def test_non_dict_payload(self):
        errors = validate_scan_config([1, 2, 3])
        assert len(errors) == 1
        assert errors[0]["path"] == "<root>"

    def test_unknown_provider_section_tolerated(self):
        # additionalProperties: True at the root level by design.
        assert validate_scan_config({"newprovider": {"foo": "bar"}}) == []

    def test_unknown_key_tolerated_by_pydantic_extra_allow(self):
        # ProviderConfigBase has extra="allow" for forward compatibility.
        assert validate_scan_config({"aws": {"completely_new_knob": 1}}) == []

    def test_provider_section_must_be_mapping(self):
        errors = validate_scan_config({"aws": "not a mapping"})
        assert _has_error_for(errors, "aws")

    def test_multiple_errors_surfaced(self):
        errors = validate_scan_config(
            {
                "aws": {
                    "max_unused_access_keys_days": 5,  # below min 30
                    "max_security_group_rules": 99999,  # above max 1000
                    "ec2_high_risk_ports": [80, 70000],  # port out of range
                }
            }
        )
        # All three should surface independently.
        assert _has_error_for(errors, "aws.max_unused_access_keys_days")
        assert _has_error_for(errors, "aws.max_security_group_rules")
        assert _has_error_for(errors, "aws.ec2_high_risk_ports")
