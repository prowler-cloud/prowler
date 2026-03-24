"""ASPM Provider data models.

These models represent the security posture of AI agent deployments as
declared in an agent manifest file (YAML/JSON).  Each model field
corresponds directly to a check category defined in the ASPM check suite.
"""

from __future__ import annotations

from datetime import date
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

# ---------------------------------------------------------------------------
# Sub-models per check category
# ---------------------------------------------------------------------------


class AgentIdentityConfig(BaseModel):
    """Identity & Authentication configuration for an AI agent."""

    type: str = Field(
        default="iam_role",
        description="Credential type: iam_role | managed_identity | service_account | api_key",
    )
    arn: Optional[str] = Field(default=None, description="Full ARN / resource ID")
    tags: Dict[str, str] = Field(
        default_factory=dict,
        description="Tags applied to the identity resource",
    )
    created_at: Optional[date] = Field(default=None, description="Creation date")
    last_used: Optional[date] = Field(
        default=None, description="Last authentication date"
    )
    uses_oidc: bool = Field(
        default=False,
        description="Whether OIDC/Workload Identity federation is used instead of static keys",
    )
    uses_static_credentials: bool = Field(
        default=True,
        description="Whether static (long-lived) credentials are used",
    )
    credential_age_days: Optional[int] = Field(
        default=None,
        description="Age of the credentials in days (None = unknown)",
    )
    rotation_policy_days: Optional[int] = Field(
        default=None,
        description="Maximum allowed credential age before rotation (days)",
    )
    naming_compliant: bool = Field(
        default=True,
        description="Whether the identity name follows organisational naming conventions",
    )
    has_owner_tag: bool = Field(
        default=False,
        description="Whether the identity has an 'owner' tag linking it to a team",
    )
    cross_cloud_registered: bool = Field(
        default=True,
        description="For multi-cloud: whether the identity is registered in all target clouds",
    )
    jwt_validation_enabled: bool = Field(
        default=False,
        description="Whether agent-to-agent JWT claims (exp, iss, sub, aud) are validated",
    )
    session_duration_seconds: Optional[int] = Field(
        default=None,
        description="Max assumed-role session duration in seconds (None = unlimited)",
    )
    has_deprovisioning_record: bool = Field(
        default=True,
        description="Whether a deprovisioning record / SOP exists for this identity",
    )
    oauth_scope_minimal: bool = Field(
        default=True,
        description="Whether OAuth tokens are requested with minimal required scopes",
    )
    unused_secondary_credentials: bool = Field(
        default=False,
        description="Whether unused secondary credentials (backup keys) exist",
    )


class AgentPermissionsConfig(BaseModel):
    """Permissions & Least Privilege configuration for an AI agent."""

    has_wildcard_actions: bool = Field(
        default=False,
        description="Whether any policy grants wildcard actions (s3:*, *:*)",
    )
    has_wildcard_resources: bool = Field(
        default=False,
        description="Whether any policy grants wildcard resource ARNs (*)",
    )
    has_admin_policy: bool = Field(
        default=False,
        description="Whether an admin or power-user managed policy is attached",
    )
    has_inline_policies: bool = Field(
        default=False,
        description="Whether inline policies (instead of managed) are attached",
    )
    can_escalate_privileges: bool = Field(
        default=False,
        description="Whether the agent can escalate to human admin roles",
    )
    cross_account_access: bool = Field(
        default=False,
        description="Whether the agent has cross-account permissions",
    )
    cross_account_accounts: int = Field(
        default=0,
        description="Number of accounts the agent can access cross-account",
    )
    has_permission_boundary: bool = Field(
        default=False,
        description="Whether a permission boundary enforces the maximum permission set",
    )
    shares_role_with_human: bool = Field(
        default=False,
        description="Whether humans share the same role as this agent",
    )
    session_duration_seconds: Optional[int] = Field(
        default=None,
        description="Max session duration in seconds for assumed roles",
    )
    permissions_last_reviewed_days: Optional[int] = Field(
        default=None,
        description="Days since permissions were last reviewed (None = never)",
    )
    data_domains_accessed: List[str] = Field(
        default_factory=list,
        description="List of data domains accessible (e.g. ['s3', 'rds', 'redshift'])",
    )
    has_condition_on_sensitive_actions: bool = Field(
        default=True,
        description="Whether conditions (IP, tag, time) restrict high-risk permissions",
    )
    all_resources_tagged: bool = Field(
        default=False,
        description="Whether agent service principals carry all required governance tags",
    )
    permission_changes_approved: bool = Field(
        default=True,
        description="Whether all permission changes are traceable to approved change requests",
    )


class AgentCredentialsConfig(BaseModel):
    """Credential Management configuration for an AI agent."""

    has_hardcoded_secrets: bool = Field(
        default=False,
        description="Whether hardcoded credentials exist in code, IaC, or manifests",
    )
    credentials_in_logs: bool = Field(
        default=False,
        description="Whether credentials appear in logs or error messages",
    )
    uses_secrets_manager: bool = Field(
        default=False,
        description="Whether credentials are retrieved from a cloud secrets manager",
    )
    api_key_in_vcs: bool = Field(
        default=False,
        description="Whether API keys or tokens have been committed to version control",
    )
    rotation_interval_days: Optional[int] = Field(
        default=None,
        description="Actual credential rotation interval in days (None = no rotation)",
    )
    secrets_in_iac: bool = Field(
        default=False,
        description="Whether secrets are embedded in Terraform / CloudFormation",
    )
    database_uses_proxy: bool = Field(
        default=False,
        description="Whether database connections use a managed proxy (RDS Proxy / Cloud SQL Proxy)",
    )
    third_party_keys_managed: bool = Field(
        default=True,
        description="Whether third-party API keys (Slack, GitHub, etc.) are in secrets manager",
    )
    credential_access_audit_trail: bool = Field(
        default=False,
        description="Whether credential access (GetSecretValue, etc.) is logged and monitored",
    )
    credentials_scoped: bool = Field(
        default=True,
        description="Whether credentials have minimal scope (not admin/full-access)",
    )
    credentials_per_environment: bool = Field(
        default=True,
        description="Whether separate credentials are used per environment (dev/staging/prod)",
    )


class AgentNetworkConfig(BaseModel):
    """Network & Communication Security configuration for an AI agent."""

    uses_https_only: bool = Field(
        default=True,
        description="Whether all agent API calls use HTTPS / TLS 1.2+",
    )
    mtls_enforced: bool = Field(
        default=False,
        description="Whether mTLS is enforced in the service mesh for agent-to-agent communication",
    )
    api_calls_authenticated: bool = Field(
        default=True,
        description="Whether all internal API calls require authentication",
    )
    has_rate_limiting: bool = Field(
        default=False,
        description="Whether rate limiting is configured on agent API endpoints",
    )
    has_egress_filtering: bool = Field(
        default=False,
        description="Whether outbound network access is filtered by destination",
    )
    network_isolated: bool = Field(
        default=False,
        description="Whether the agent runs in an isolated network segment",
    )
    api_gateway_enforced: bool = Field(
        default=True,
        description="Whether all API access routes through an authenticated API Gateway",
    )
    validates_tls_certificates: bool = Field(
        default=True,
        description="Whether TLS certificates are fully validated (chain, hostname, expiry)",
    )
    network_calls_logged: bool = Field(
        default=False,
        description="Whether all network calls are logged with source agent ID and destination",
    )
    uses_dnssec: bool = Field(
        default=False,
        description="Whether DNS queries use DNSSEC / DoH / DoT",
    )
    validates_webhooks: bool = Field(
        default=True,
        description="Whether incoming webhooks/callbacks are signature-validated",
    )


class AgentDataAccessConfig(BaseModel):
    """Data Access & Privacy configuration for an AI agent."""

    accesses_pii: bool = Field(
        default=False,
        description="Whether the agent can access Personally Identifiable Information",
    )
    has_dlp_controls: bool = Field(
        default=False,
        description="Whether Data Loss Prevention controls are enforced on PII access",
    )
    data_encrypted_at_rest: bool = Field(
        default=True,
        description="Whether all data stores accessed by the agent use encryption at rest",
    )
    data_encrypted_in_transit: bool = Field(
        default=True,
        description="Whether all data in transit is encrypted (TLS)",
    )
    cross_boundary_data_flows_approved: bool = Field(
        default=True,
        description="Whether cross-boundary data flows are whitelisted and documented",
    )
    training_data_integrity_verified: bool = Field(
        default=False,
        description="Whether training data sources are validated with integrity checks",
    )
    data_retention_policy_days: Optional[int] = Field(
        default=None,
        description="Maximum data retention period in days (None = no policy)",
    )
    database_query_audit_enabled: bool = Field(
        default=False,
        description="Whether database queries from the agent are fully audited",
    )
    object_storage_access_logged: bool = Field(
        default=False,
        description="Whether object storage (S3/Blob/GCS) access is logged",
    )
    llm_context_sanitized: bool = Field(
        default=False,
        description="Whether sensitive data is stripped from LLM context windows",
    )
    has_model_card: bool = Field(
        default=False,
        description="Whether the agent's model has a documented model card",
    )
    output_validated_for_sensitive_data: bool = Field(
        default=False,
        description="Whether agent outputs are validated and redacted for sensitive data",
    )
    supports_data_subject_rights: bool = Field(
        default=False,
        description="Whether the system supports GDPR/CCPA data subject access requests",
    )


class AgentRuntimeConfig(BaseModel):
    """Runtime & Sandbox Security configuration for an AI agent."""

    runs_as_root: bool = Field(
        default=False,
        description="Whether the agent container/process runs as root",
    )
    privileged_container: bool = Field(
        default=False,
        description="Whether the agent runs in a privileged container",
    )
    has_seccomp_profile: bool = Field(
        default=False,
        description="Whether a seccomp profile is applied to the container",
    )
    has_apparmor_selinux: bool = Field(
        default=False,
        description="Whether AppArmor or SELinux policy is applied",
    )
    has_resource_limits: bool = Field(
        default=False,
        description="Whether CPU, memory, and disk limits are configured",
    )
    image_scanned_for_cves: bool = Field(
        default=False,
        description="Whether the container image is scanned for vulnerabilities before deployment",
    )
    has_runtime_monitoring: bool = Field(
        default=False,
        description="Whether runtime security monitoring (Falco, Sysdig, etc.) is enabled",
    )
    execution_environment_versioned: bool = Field(
        default=False,
        description="Whether the execution environment uses pinned base images and IaC",
    )
    secrets_cleared_from_memory: bool = Field(
        default=False,
        description="Whether sensitive data is cleared from memory after use",
    )
    has_execution_timeout: bool = Field(
        default=False,
        description="Whether execution time limits are enforced",
    )
    behavior_deterministic: bool = Field(
        default=True,
        description="Whether the agent produces deterministic, reproducible behaviour",
    )
    dependencies_integrity_checked: bool = Field(
        default=False,
        description="Whether runtime dependencies are verified via checksums/signatures",
    )
    uses_platform_security_controls: bool = Field(
        default=False,
        description="Whether platform-native controls (Pod Security Standards, Binary Authorization) are applied",
    )


class AgentSupplyChainConfig(BaseModel):
    """Supply Chain Security configuration for an AI agent."""

    framework_cves_scanned: bool = Field(
        default=False,
        description="Whether agent frameworks (LangChain, etc.) are scanned for CVEs",
    )
    llm_model_provenance_verified: bool = Field(
        default=False,
        description="Whether the LLM model has verified provenance (checksum, signed source)",
    )
    plugins_security_reviewed: bool = Field(
        default=False,
        description="Whether all agent plugins/tools have been security-reviewed",
    )
    dependencies_version_pinned: bool = Field(
        default=False,
        description="Whether all dependencies use exact pinned versions with lock files",
    )
    artifacts_signed: bool = Field(
        default=False,
        description="Whether container images and artifacts are cryptographically signed",
    )
    cicd_has_security_gates: bool = Field(
        default=False,
        description="Whether the CI/CD pipeline includes secret scanning, SAST, and dependency scanning",
    )
    licenses_compliant: bool = Field(
        default=True,
        description="Whether all model and library licenses are documented and compliant",
    )
    model_update_cadence_days: Optional[int] = Field(
        default=None,
        description="Maximum allowed days between security updates to the LLM model",
    )
    dependency_checksums_verified: bool = Field(
        default=False,
        description="Whether package checksums/signatures are verified on download",
    )


class AgentObservabilityConfig(BaseModel):
    """Observability & Monitoring configuration for an AI agent."""

    execution_logs_complete: bool = Field(
        default=False,
        description="Whether execution logs capture actions, tools, decisions, and outputs",
    )
    anomaly_detection_enabled: bool = Field(
        default=False,
        description="Whether anomaly detection monitors for unusual agent behaviour",
    )
    prompt_injection_monitoring: bool = Field(
        default=False,
        description="Whether LLM inputs are monitored for prompt injection / jailbreak attempts",
    )
    audit_logs_immutable: bool = Field(
        default=False,
        description="Whether audit logs are immutable and integrity-protected",
    )
    metrics_exported: bool = Field(
        default=False,
        description="Whether key metrics (latency, error rate, resource usage) are exported",
    )
    security_event_alerting: bool = Field(
        default=False,
        description="Whether security events trigger alerts within 5 minutes",
    )
    distributed_tracing_enabled: bool = Field(
        default=False,
        description="Whether W3C trace context is propagated across agent service calls",
    )
    centralized_dashboard: bool = Field(
        default=False,
        description="Whether a centralised dashboard shows agent security posture",
    )
    configuration_drift_tracked: bool = Field(
        default=False,
        description="Whether configuration changes are tracked and drift from baseline detected",
    )
    performance_baseline_defined: bool = Field(
        default=False,
        description="Whether a performance baseline exists and degradation triggers alerts",
    )


class AgentComplianceConfig(BaseModel):
    """Compliance & Governance configuration for an AI agent."""

    owasp_llm_top10_assessed: bool = Field(
        default=False,
        description="Whether the agent has been assessed against the OWASP LLM Top 10",
    )
    eu_ai_act_controls_present: bool = Field(
        default=False,
        description="Whether EU AI Act compliance controls are documented",
    )
    nist_ai_rmf_assessed: bool = Field(
        default=False,
        description="Whether the agent has been assessed against the NIST AI RMF",
    )
    access_control_policy_enforced: bool = Field(
        default=False,
        description="Whether a documented access control policy is enforced and audited",
    )
    dpia_completed: bool = Field(
        default=False,
        description="Whether a Data Privacy Impact Assessment has been completed",
    )
    regulatory_requirements_mapped: bool = Field(
        default=False,
        description="Whether applicable regulations (HIPAA, PCI-DSS, etc.) are mapped",
    )
    incident_response_plan_exists: bool = Field(
        default=False,
        description="Whether an agent-specific incident response plan exists and is tested",
    )
    third_party_vendors_assessed: bool = Field(
        default=False,
        description="Whether third-party agent vendors have been security-assessed (SOC 2, ISO 27001)",
    )
    user_consent_and_disclosure: bool = Field(
        default=False,
        description="Whether users are informed and consent to agent actions on their behalf",
    )


class AgentAttackPathsConfig(BaseModel):
    """Attack Path Analysis configuration for an AI agent."""

    cross_cloud_escalation_possible: bool = Field(
        default=False,
        description="Whether the agent can chain identities to escalate privileges across clouds",
    )
    tool_abuse_escalation_possible: bool = Field(
        default=False,
        description="Whether agent tools can be abused to exceed the agent's declared permissions",
    )
    sensitive_data_enables_downstream_compromise: bool = Field(
        default=False,
        description="Whether data accessible to the agent contains credentials or social-engineering material",
    )
    lateral_movement_via_shared_infra: bool = Field(
        default=False,
        description="Whether the agent can access sibling agent infrastructure / shared services",
    )
    compromise_enables_full_account_takeover: bool = Field(
        default=False,
        description="Whether a compromised agent credential chain could lead to full account takeover",
    )
    llm_output_used_in_code_execution: bool = Field(
        default=False,
        description="Whether LLM output is used directly in system calls or exec() without validation",
    )


# ---------------------------------------------------------------------------
# Top-level Agent model
# ---------------------------------------------------------------------------


class AgentConfig(BaseModel):
    """Full security posture declaration for a single AI agent deployment."""

    id: str = Field(description="Unique identifier for this agent deployment")
    name: str = Field(description="Human-readable agent name")
    environment: str = Field(
        default="unknown",
        description="Deployment environment: prod | staging | dev | unknown",
    )
    cloud_provider: str = Field(
        default="unknown",
        description="Primary cloud provider: aws | azure | gcp | unknown",
    )
    region: str = Field(default="global", description="Primary deployment region")

    identity: AgentIdentityConfig = Field(default_factory=AgentIdentityConfig)
    permissions: AgentPermissionsConfig = Field(default_factory=AgentPermissionsConfig)
    credentials: AgentCredentialsConfig = Field(default_factory=AgentCredentialsConfig)
    network: AgentNetworkConfig = Field(default_factory=AgentNetworkConfig)
    data_access: AgentDataAccessConfig = Field(default_factory=AgentDataAccessConfig)
    runtime: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    supply_chain: AgentSupplyChainConfig = Field(default_factory=AgentSupplyChainConfig)
    observability: AgentObservabilityConfig = Field(
        default_factory=AgentObservabilityConfig
    )
    compliance: AgentComplianceConfig = Field(default_factory=AgentComplianceConfig)
    attack_paths: AgentAttackPathsConfig = Field(default_factory=AgentAttackPathsConfig)

    def dict(self, **kwargs):
        """Return a serialisable dict (used by Check_Report)."""
        return super().model_dump(**kwargs)


# ---------------------------------------------------------------------------
# Output options
# ---------------------------------------------------------------------------


class ASPMOutputOptions(ProviderOutputOptions):
    """ASPM-specific output options."""

    def __init__(self, arguments, bulk_checks_metadata):
        super().__init__(arguments, bulk_checks_metadata)
        if not getattr(arguments, "output_filename", None):
            self.output_filename = f"prowler-output-aspm-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
