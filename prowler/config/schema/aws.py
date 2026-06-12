"""AWS provider config schema.

Bounds on every field are intentionally conservative: they are not the
absolute service maxima but the values that produce a useful security
check. A user is free to keep the built-in default by omitting the key —
out-of-range values are dropped with a warning at SDK runtime, and
rejected at the Prowler App backend.

Whenever an upper bound is uncertain, the cap is set to a value that
still keeps the check meaningful (e.g. a 10-year window for date-based
thresholds) and avoids ints that obviously break downstream maths
(`min_kinesis_stream_retention_hours = 99999`).
"""

from ipaddress import ip_network
from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, Field

from prowler.config.schema.base import ProviderConfigBase

# ---- Reusable constants -----------------------------------------------------

# CloudWatch Logs only accepts these retention values (in days). Anything else
# is silently coerced to the next valid value by the API — we reject upfront.
_CLOUDWATCH_RETENTION_DAYS = (
    1,
    3,
    5,
    7,
    14,
    30,
    60,
    90,
    120,
    150,
    180,
    365,
    400,
    545,
    731,
    1827,
    2192,
    2557,
    2922,
    3288,
    3653,
)

_VALID_CW_RETENTION_LITERAL = Literal[
    1,
    3,
    5,
    7,
    14,
    30,
    60,
    90,
    120,
    150,
    180,
    365,
    400,
    545,
    731,
    1827,
    2192,
    2557,
    2922,
    3288,
    3653,
]


# ---- Custom validators ------------------------------------------------------


def _validate_port_range(v: Optional[list[int]]) -> Optional[list[int]]:
    if v is None:
        return v
    for port in v:
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is outside the valid range 1..65535")
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


def _validate_semver(v: Optional[str]) -> Optional[str]:
    """Accept "1.4.0" style strings (used by Fargate platform versions)."""
    if v is None:
        return v
    parts = v.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"{v!r} is not a valid semantic version (expected X.Y.Z)")
    return v


def _validate_eks_minor(v: Optional[str]) -> Optional[str]:
    """Accept "1.28" style strings (EKS minor versions)."""
    if v is None:
        return v
    parts = v.split(".")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise ValueError(f"{v!r} is not a valid EKS version (expected X.Y)")
    return v


# ---- Nested models ----------------------------------------------------------


class _DetectSecretsPlugin(ProviderConfigBase):
    """One entry inside ``detect_secrets_plugins``.

    Only ``name`` is required by the upstream library. ``limit`` is used by
    the entropy detectors. Any other plugin-specific kwarg is preserved by
    the ``extra="allow"`` policy inherited from ProviderConfigBase.
    """

    name: str
    limit: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description=(
            "Entropy threshold for detect-secrets entropy plugins. Range: 0..10 "
            "(Shannon entropy is bounded by log2(256)=8; >10 is meaningless)."
        ),
    )


# ---- Main schema ------------------------------------------------------------


class AWSProviderConfig(ProviderConfigBase):
    # --- IAM ---------------------------------------------------------------
    mute_non_default_regions: Optional[bool] = None
    disallowed_regions: Optional[list[str]] = None
    max_unused_access_keys_days: Optional[int] = Field(
        default=None,
        ge=30,
        le=180,
        description=(
            "Days an IAM user access key can stay unused before being flagged. "
            "Range: 30..180 days (CIS AWS 1.13 recommends 45; NIST IA-5 ≤90)."
        ),
    )
    max_console_access_days: Optional[int] = Field(
        default=None,
        ge=30,
        le=180,
        description=(
            "Days an IAM console password can stay unused before being flagged. "
            "Range: 30..180 days (CIS AWS 1.12 recommends 45)."
        ),
    )
    max_unused_sagemaker_access_days: Optional[int] = Field(
        default=None,
        ge=7,
        le=180,
        description=(
            "Days a SageMaker user access key can stay unused. Range: 7..180 "
            "(SageMaker tokens are usually high-privilege over S3/KMS)."
        ),
    )

    # --- EC2 ---------------------------------------------------------------
    shodan_api_key: Optional[str] = Field(
        default=None,
        max_length=512,
        description="API key for Shodan lookups on EC2 public IPs.",
    )
    max_security_group_rules: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000,
        description="Max ingress+egress rules per security group. AWS hard limit is 1000.",
    )
    max_ec2_instance_age_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=1095,
        description=(
            "Days an EC2 instance can run before being flagged as old. "
            "Range: 1..1095 (3 years; instances should be refreshed for patching "
            "per NIST CM-3 — anything older is a security smell)."
        ),
    )
    ec2_allowed_interface_types: Optional[list[str]] = None
    ec2_allowed_instance_owners: Optional[list[str]] = None
    ec2_high_risk_ports: Annotated[
        Optional[list[int]], AfterValidator(_validate_port_range)
    ] = Field(
        default=None,
        description="TCP/UDP ports considered high-risk when reachable from the Internet (1..65535; port 0 is reserved).",
    )

    # --- ECS ---------------------------------------------------------------
    fargate_linux_latest_version: Annotated[
        Optional[str], AfterValidator(_validate_semver)
    ] = Field(default=None, description="Fargate Linux platform version (X.Y.Z).")
    fargate_windows_latest_version: Annotated[
        Optional[str], AfterValidator(_validate_semver)
    ] = Field(default=None, description="Fargate Windows platform version (X.Y.Z).")

    # --- Cross-account trust ----------------------------------------------
    trusted_account_ids: Annotated[
        Optional[list[str]], AfterValidator(_validate_account_ids)
    ] = Field(
        default=None,
        description="Additional 12-digit AWS account IDs trusted by cross-account checks.",
    )
    trusted_ips: Annotated[
        Optional[list[str]], AfterValidator(_validate_trusted_ips)
    ] = Field(
        default=None,
        description="IPv4/IPv6 addresses or CIDR ranges that are NOT considered public.",
    )

    # --- CloudWatch / CloudFormation --------------------------------------
    log_group_retention_days: Optional[_VALID_CW_RETENTION_LITERAL] = Field(
        default=None,
        description=(
            "Required CloudWatch Logs retention in days. Must match one of the "
            f"values accepted by the AWS API: {list(_CLOUDWATCH_RETENTION_DAYS)}."
        ),
    )
    recommended_cdk_bootstrap_version: Optional[int] = Field(
        default=None,
        ge=1,
        le=100,
        description="Min CDK bootstrap version expected on the account.",
    )

    # --- AppStream --------------------------------------------------------
    max_idle_disconnect_timeout_in_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=1800,
        description=(
            "AppStream idle disconnect timeout (seconds). Range: 60..1800 "
            "(NIST AC-12: sensitive sessions ≤15 min — cap at 30 min)."
        ),
    )
    max_disconnect_timeout_in_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=3600,
        description="AppStream disconnect timeout (seconds). Range: 60..3600.",
    )
    max_session_duration_seconds: Optional[int] = Field(
        default=None,
        ge=600,
        le=86400,
        description=(
            "AppStream max session duration (seconds). Range: 600..86400 "
            "(10 min .. 24 h — AWS AppStream hard limit per session)."
        ),
    )

    # --- Lambda -----------------------------------------------------------
    obsolete_lambda_runtimes: Optional[list[str]] = None
    lambda_min_azs: Optional[int] = Field(
        default=None,
        ge=1,
        le=6,
        description="Min number of AZs a VPC-bound Lambda must span. Range: 1..6.",
    )

    # --- Organizations ----------------------------------------------------
    organizations_enabled_regions: Optional[list[str]] = None
    organizations_trusted_delegated_administrators: Annotated[
        Optional[list[str]], AfterValidator(_validate_account_ids)
    ] = None
    organizations_trusted_ids: Optional[list[str]] = None

    # --- ECR --------------------------------------------------------------
    ecr_repository_vulnerability_minimum_severity: Optional[
        Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    ] = Field(
        default=None,
        description="Highest severity tolerated for ECR images.",
    )

    # --- Trusted Advisor --------------------------------------------------
    verify_premium_support_plans: Optional[bool] = None

    # --- CloudTrail threat detection: privilege escalation ----------------
    threat_detection_privilege_escalation_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of suspicious actions that triggers the priv-esc detection.",
    )
    threat_detection_privilege_escalation_minutes: Optional[int] = Field(
        default=None,
        ge=5,
        le=43200,
        description=(
            "Lookback window (minutes) for priv-esc detection. Range: 5..43200 "
            "(under 5 min the signal is dominated by false positives)."
        ),
    )
    threat_detection_privilege_escalation_actions: Optional[list[str]] = None

    # --- CloudTrail threat detection: enumeration -------------------------
    threat_detection_enumeration_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of suspicious actions that triggers the enumeration detection.",
    )
    threat_detection_enumeration_minutes: Optional[int] = Field(
        default=None,
        ge=5,
        le=43200,
        description="Lookback window (minutes) for enumeration detection. Range: 5..43200.",
    )
    threat_detection_enumeration_actions: Optional[list[str]] = None

    # --- CloudTrail threat detection: LLM jacking -------------------------
    threat_detection_llm_jacking_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of suspicious actions that triggers the LLM-jacking detection.",
    )
    threat_detection_llm_jacking_minutes: Optional[int] = Field(
        default=None,
        ge=5,
        le=43200,
        description="Lookback window (minutes) for LLM-jacking detection. Range: 5..43200.",
    )
    threat_detection_llm_jacking_actions: Optional[list[str]] = None

    # --- RDS --------------------------------------------------------------
    check_rds_instance_replicas: Optional[bool] = None

    # --- ACM --------------------------------------------------------------
    days_to_expire_threshold: Optional[int] = Field(
        default=None,
        ge=7,
        le=365,
        description=(
            "Days before certificate expiration to flag. Range: 7..365 "
            "(PCI-DSS 4.2.1.1: alert ≥30 days before expiry; <7 days is too "
            "tight to actually act on)."
        ),
    )
    insecure_key_algorithms: Optional[list[str]] = None

    # --- EKS --------------------------------------------------------------
    eks_required_log_types: Optional[
        list[
            Literal[
                "api",
                "audit",
                "authenticator",
                "controllerManager",
                "scheduler",
            ]
        ]
    ] = Field(
        default=None,
        description="EKS control plane log types that must be enabled.",
    )
    eks_cluster_oldest_version_supported: Annotated[
        Optional[str], AfterValidator(_validate_eks_minor)
    ] = Field(
        default=None,
        description='Minimum supported EKS minor version, expected as "X.Y".',
    )

    # --- CodeBuild --------------------------------------------------------
    excluded_sensitive_environment_variables: Optional[list[str]] = None
    codebuild_github_allowed_organizations: Optional[list[str]] = None

    # --- ELB / ELBv2 ------------------------------------------------------
    elb_min_azs: Optional[int] = Field(
        default=None,
        ge=1,
        le=6,
        description="Min AZs a Classic ELB must span. Range: 1..6.",
    )
    elbv2_min_azs: Optional[int] = Field(
        default=None,
        ge=1,
        le=6,
        description="Min AZs an Application/Network LB must span. Range: 1..6.",
    )

    # --- ElastiCache -----------------------------------------------------
    minimum_snapshot_retention_period: Optional[int] = Field(
        default=None,
        ge=1,
        le=35,
        description="Days an ElastiCache backup must be retained. Range: 1..35 (service hard limit).",
    )

    # --- Secrets ---------------------------------------------------------
    secrets_ignore_patterns: Optional[list[str]] = None
    max_days_secret_unused: Optional[int] = Field(
        default=None,
        ge=7,
        le=365,
        description="Days a Secrets Manager secret can stay unused. Range: 7..365.",
    )
    max_days_secret_unrotated: Optional[int] = Field(
        default=None,
        ge=1,
        le=180,
        description=(
            "Days a Secrets Manager secret can go without rotation. Range: 1..180 "
            "(NIST IA-5: rotate quarterly; CIS recommends ≤90)."
        ),
    )

    # --- Kinesis ---------------------------------------------------------
    min_kinesis_stream_retention_hours: Optional[int] = Field(
        default=None,
        ge=24,
        le=8760,
        description="Hours of Kinesis stream retention. Range: 24..8760 (1 day .. 1 year).",
    )

    # --- detect-secrets plugin list -------------------------------------
    detect_secrets_plugins: Optional[list[_DetectSecretsPlugin]] = None
