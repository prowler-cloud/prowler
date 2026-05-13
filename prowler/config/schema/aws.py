from ipaddress import ip_network
from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, Field

from prowler.config.schema.base import ProviderConfigBase


class _DetectSecretsPlugin(ProviderConfigBase):
    """One entry inside ``detect_secrets_plugins``.

    Only ``name`` is required by the upstream library. ``limit`` is used by
    the entropy detectors. Any other plugin-specific kwarg is preserved by
    the ``extra="allow"`` policy inherited from ProviderConfigBase.
    """

    name: str
    limit: Optional[float] = None


def _validate_port_range(v: Optional[list[int]]) -> Optional[list[int]]:
    if v is None:
        return v
    for port in v:
        if not 0 <= port <= 65535:
            raise ValueError(f"port {port} is outside the valid range 0..65535")
    return v


def _validate_account_ids(v: Optional[list[str]]) -> Optional[list[str]]:
    if v is None:
        return v
    for account_id in v:
        if not (account_id.isdigit() and len(account_id) == 12):
            raise ValueError(
                f"trusted_account_ids entry {account_id!r} is not a 12-digit AWS account id"
            )
    return v


def _validate_trusted_ips(v: Optional[list[str]]) -> Optional[list[str]]:
    if v is None:
        return v
    for entry in v:
        try:
            ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"trusted_ips entry {entry!r} is not a valid IP or CIDR ({exc})"
            ) from exc
    return v


class AWSProviderConfig(ProviderConfigBase):
    # IAM
    mute_non_default_regions: Optional[bool] = None
    disallowed_regions: Optional[list[str]] = None
    max_unused_access_keys_days: Optional[int] = Field(default=None, gt=0)
    max_console_access_days: Optional[int] = Field(default=None, gt=0)
    max_unused_sagemaker_access_days: Optional[int] = Field(default=None, gt=0)

    # EC2
    shodan_api_key: Optional[str] = None
    max_security_group_rules: Optional[int] = Field(default=None, gt=0)
    max_ec2_instance_age_in_days: Optional[int] = Field(default=None, gt=0)
    ec2_allowed_interface_types: Optional[list[str]] = None
    ec2_allowed_instance_owners: Optional[list[str]] = None
    ec2_high_risk_ports: Annotated[
        Optional[list[int]], AfterValidator(_validate_port_range)
    ] = None

    # ECS
    fargate_linux_latest_version: Optional[str] = None
    fargate_windows_latest_version: Optional[str] = None

    # Cross-account trust
    trusted_account_ids: Annotated[
        Optional[list[str]], AfterValidator(_validate_account_ids)
    ] = None
    trusted_ips: Annotated[
        Optional[list[str]], AfterValidator(_validate_trusted_ips)
    ] = None

    # CloudWatch / CloudFormation
    log_group_retention_days: Optional[int] = Field(default=None, gt=0)
    recommended_cdk_bootstrap_version: Optional[int] = Field(default=None, gt=0)

    # AppStream
    max_idle_disconnect_timeout_in_seconds: Optional[int] = Field(default=None, gt=0)
    max_disconnect_timeout_in_seconds: Optional[int] = Field(default=None, gt=0)
    max_session_duration_seconds: Optional[int] = Field(default=None, gt=0)

    # Lambda
    obsolete_lambda_runtimes: Optional[list[str]] = None
    lambda_min_azs: Optional[int] = Field(default=None, gt=0)

    # Organizations
    organizations_enabled_regions: Optional[list[str]] = None
    organizations_trusted_delegated_administrators: Optional[list[str]] = None
    organizations_trusted_ids: Optional[list[str]] = None

    # ECR
    ecr_repository_vulnerability_minimum_severity: Optional[
        Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ] = None

    # Trusted Advisor
    verify_premium_support_plans: Optional[bool] = None

    # CloudTrail threat detection
    threat_detection_privilege_escalation_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0
    )
    threat_detection_privilege_escalation_minutes: Optional[int] = Field(
        default=None, gt=0
    )
    threat_detection_privilege_escalation_actions: Optional[list[str]] = None

    threat_detection_enumeration_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0
    )
    threat_detection_enumeration_minutes: Optional[int] = Field(default=None, gt=0)
    threat_detection_enumeration_actions: Optional[list[str]] = None

    threat_detection_llm_jacking_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0
    )
    threat_detection_llm_jacking_minutes: Optional[int] = Field(default=None, gt=0)
    threat_detection_llm_jacking_actions: Optional[list[str]] = None

    # RDS
    check_rds_instance_replicas: Optional[bool] = None

    # ACM
    days_to_expire_threshold: Optional[int] = Field(default=None, gt=0)
    insecure_key_algorithms: Optional[list[str]] = None

    # EKS
    eks_required_log_types: Optional[list[str]] = None
    eks_cluster_oldest_version_supported: Optional[str] = None

    # CodeBuild
    excluded_sensitive_environment_variables: Optional[list[str]] = None
    codebuild_github_allowed_organizations: Optional[list[str]] = None

    # ELB / ELBv2
    elb_min_azs: Optional[int] = Field(default=None, gt=0)
    elbv2_min_azs: Optional[int] = Field(default=None, gt=0)

    # ElastiCache
    minimum_snapshot_retention_period: Optional[int] = Field(default=None, gt=0)

    # Secrets
    secrets_ignore_patterns: Optional[list[str]] = None
    max_days_secret_unused: Optional[int] = Field(default=None, gt=0)
    max_days_secret_unrotated: Optional[int] = Field(default=None, gt=0)

    # Kinesis
    min_kinesis_stream_retention_hours: Optional[int] = Field(default=None, gt=0)

    # detect-secrets plugins
    detect_secrets_plugins: Optional[list[_DetectSecretsPlugin]] = None
