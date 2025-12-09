"""Pydantic models for simplified security findings responses."""

from typing import Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel, ConfigDict, Field


class CheckRemediation(MinimalSerializerMixin, BaseModel):
    """Remediation information for a security check."""

    model_config = ConfigDict(frozen=True)

    cli: str | None = Field(
        default=None,
        description="Command-line interface commands for remediation",
    )
    terraform: str | None = Field(
        default=None,
        description="Terraform code snippet with best practices for remediation",
    )
    nativeiac: str | None = Field(
        default=None,
        description="Native Infrastructure as Code code snippet with best practices for remediation",
    )
    other: str | None = Field(
        default=None,
        description="Other remediation code snippet with best practices for remediation, usually used for web interfaces or other tools",
    )
    recommendation: str | None = Field(
        default=None,
        description="Text description with general best recommended practices to avoid the issue",
    )


class CheckMetadata(MinimalSerializerMixin, BaseModel):
    """Essential metadata for a security check."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(
        description="Human-readable title of the security check",
    )
    description: str = Field(
        description="Detailed description of what the check validates",
    )
    provider: str = Field(
        description="Prowler provider this check belongs to (e.g., 'aws', 'azure', 'gcp')",
    )
    service: str = Field(
        description="Prowler service being checked (e.g., 's3', 'ec2', 'keyvault')",
    )
    resource_type: str = Field(
        description="Type of resource being evaluated (e.g., 'AwsS3Bucket')",
    )
    risk: str | None = Field(
        default=None,
        description="Risk description if the check fails",
    )
    remediation: CheckRemediation | None = Field(
        default=None,
        description="Remediation guidance including CLI commands and recommendations",
    )
    additional_urls: list[str] = Field(
        default_factory=list,
        description="List of additional URLs related to the check",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Categories this check belongs to (e.g., ['encryption', 'logging'])",
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "CheckMetadata":
        """Transform API check_metadata to simplified format."""
        remediation_data = data.get("remediation")

        remediation = None
        if remediation_data:
            code = remediation_data.get("code", {})
            recommendation = remediation_data.get("recommendation", {})

            remediation = CheckRemediation(
                cli=code["cli"],
                terraform=code["terraform"],
                nativeiac=code["nativeiac"],
                other=code["other"],
                recommendation=recommendation["text"],
            )

        return cls(
            title=data["checktitle"],
            description=data["description"],
            provider=data["provider"],
            risk=data["risk"],
            service=data["servicename"],
            resource_type=data["resourcetype"],
            remediation=remediation,
            additional_urls=data["additionalurls"],
            categories=data["categories"],
        )


class SimplifiedFinding(MinimalSerializerMixin, BaseModel):
    """Simplified security finding with only LLM-relevant information."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this finding in Prowler database"
    )
    uid: str = Field(
        description="Human-readable unique identifier assigned by Prowler. Format: prowler-{provider}-{check_id}-{account_uid}-{region}-{resource_name}",
    )
    status: Literal["FAIL", "PASS", "MANUAL"] = Field(
        description="Result status: FAIL (security issue found), PASS (no issue), MANUAL (requires manual verification)",
    )
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(
        description="Severity level of the finding",
    )
    check_id: str = Field(
        description="ID of the security check that generated this finding",
    )
    status_extended: str = Field(
        description="Extended status information providing additional context",
    )
    delta: Literal["new", "changed"] | None = Field(
        default=None,
        description="Change status: 'new' (not seen before), 'changed' (modified since last scan), or None (unchanged)",
    )
    muted: bool | None = Field(
        default=None,
        description="Whether this finding has been muted/suppressed by the user",
    )
    muted_reason: str | None = Field(
        default=None,
        description="Reason provided when muting this finding",
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFinding":
        """Transform JSON:API finding response to simplified format."""
        attributes = data["attributes"]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_id=attributes["check_metadata"]["checkid"],
            status_extended=attributes["status_extended"],
            delta=attributes["delta"],
            muted=attributes["muted"],
            muted_reason=attributes["muted_reason"],
        )


class DetailedFinding(SimplifiedFinding):
    """Detailed security finding with comprehensive information for deep analysis.

    Extends SimplifiedFinding with temporal metadata and relationships to scans and resources.
    Use this when you need complete context about a specific finding.
    """

    model_config = ConfigDict(frozen=True)

    inserted_at: str = Field(
        description="ISO 8601 timestamp when this finding was first inserted into the database",
    )
    updated_at: str = Field(
        description="ISO 8601 timestamp when this finding was last updated",
    )
    first_seen_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this finding was first detected across all scans",
    )
    scan_id: str | None = Field(
        default=None,
        description="UUID of the scan that generated this finding",
    )
    resource_ids: list[str] = Field(
        default_factory=list,
        description="List of UUIDs for cloud resources associated with this finding",
    )
    check_metadata: CheckMetadata = Field(
        description="Metadata about the security check that generated this finding",
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedFinding":
        """Transform JSON:API finding response to detailed format."""
        attributes = data["attributes"]
        check_metadata = attributes["check_metadata"]
        relationships = data.get("relationships", {})

        # Parse scan relationship
        scan_id = None
        scan_data = relationships.get("scan", {}).get("data")
        if scan_data:
            scan_id = scan_data["id"]

        # Parse resources relationship
        resource_ids = []
        resources_data = relationships.get("resources", {}).get("data", [])
        if resources_data:
            resource_ids = [r["id"] for r in resources_data]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_id=check_metadata["checkid"],
            check_metadata=CheckMetadata.from_api_response(check_metadata),
            status_extended=attributes.get("status_extended"),
            delta=attributes.get("delta"),
            muted=attributes["muted"],
            muted_reason=attributes.get("muted_reason"),
            inserted_at=attributes["inserted_at"],
            updated_at=attributes["updated_at"],
            first_seen_at=attributes.get("first_seen_at"),
            scan_id=scan_id,
            resource_ids=resource_ids,
        )


class FindingsListResponse(BaseModel):
    """Simplified response for findings list queries."""

    model_config = ConfigDict(frozen=True)

    findings: list[SimplifiedFinding] = Field(
        description="List of security findings matching the query",
    )
    total_num_finding: int = Field(
        description="Total number of findings matching the query across all pages",
        ge=0,
    )
    total_num_pages: int = Field(
        description="Total number of pages available",
        ge=0,
    )
    current_page: int = Field(
        description="Current page number (1-indexed)",
        ge=1,
    )

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingsListResponse":
        """Transform JSON:API response to simplified format."""
        data = response["data"]
        meta = response["meta"]
        pagination = meta["pagination"]

        findings = [SimplifiedFinding.from_api_response(item) for item in data]

        return cls(
            findings=findings,
            total_num_finding=pagination["count"],
            total_num_pages=pagination["pages"],
            current_page=pagination["page"],
        )


class FindingsOverview(BaseModel):
    """Simplified findings overview with aggregate statistics."""

    model_config = ConfigDict(frozen=True)

    total: int = Field(
        description="Total number of findings",
        ge=0,
    )
    fail: int = Field(
        description="Total number of failed security checks",
        ge=0,
    )
    passed: int = (  # Using 'passed' instead of 'pass' since 'pass' is a Python keyword
        Field(
            description="Total number of passed security checks",
            ge=0,
        )
    )
    muted: int = Field(
        description="Total number of muted findings",
        ge=0,
    )
    new: int = Field(
        description="Total number of new findings (not seen in previous scans)",
        ge=0,
    )
    changed: int = Field(
        description="Total number of changed findings (modified since last scan)",
        ge=0,
    )
    fail_new: int = Field(
        description="Number of new findings with FAIL status",
        ge=0,
    )
    fail_changed: int = Field(
        description="Number of changed findings with FAIL status",
        ge=0,
    )
    pass_new: int = Field(
        description="Number of new findings with PASS status",
        ge=0,
    )
    pass_changed: int = Field(
        description="Number of changed findings with PASS status",
        ge=0,
    )
    muted_new: int = Field(
        description="Number of new muted findings",
        ge=0,
    )
    muted_changed: int = Field(
        description="Number of changed muted findings",
        ge=0,
    )

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingsOverview":
        """Transform JSON:API overview response to simplified format."""
        data = response["data"]
        attributes = data["attributes"]

        return cls(
            total=attributes["total"],
            fail=attributes["fail"],
            passed=attributes["pass"],
            muted=attributes["muted"],
            new=attributes["new"],
            changed=attributes["changed"],
            fail_new=attributes["fail_new"],
            fail_changed=attributes["fail_changed"],
            pass_new=attributes["pass_new"],
            pass_changed=attributes["pass_changed"],
            muted_new=attributes["muted_new"],
            muted_changed=attributes["muted_changed"],
        )
