"""Pydantic models for simplified security findings responses."""

from typing import Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel


class CheckRemediation(MinimalSerializerMixin, BaseModel):
    """Remediation information for a security check."""

    cli: str | None = None
    terraform: str | None = None
    recommendation_text: str | None = None
    recommendation_url: str | None = None


class CheckMetadata(MinimalSerializerMixin, BaseModel):
    """Essential metadata for a security check."""

    check_id: str
    title: str
    description: str
    provider: str
    risk: str | None = None
    service: str
    resource_type: str
    remediation: CheckRemediation | None = None
    related_url: str | None = None
    categories: list[str] | None = None

    @classmethod
    def from_api_response(cls, data: dict) -> "CheckMetadata":
        """Transform API check_metadata to simplified format."""
        remediation_data = data.get("remediation")

        remediation = None
        if remediation_data:
            code = remediation_data.get("code", {})
            recommendation = remediation_data.get("recommendation", {})

            remediation = CheckRemediation(
                cli=code.get("cli"),
                terraform=code.get("terraform"),
                recommendation_text=recommendation.get("text"),
                recommendation_url=recommendation.get("url"),
            )

        return cls(
            check_id=data["checkid"],
            title=data["checktitle"],
            description=data["description"],
            provider=data["provider"],
            risk=data.get("risk"),
            service=data["servicename"],
            resource_type=data["resourcetype"],
            remediation=remediation,
            related_url=data.get("relatedurl"),
            categories=data.get("categories"),
        )


class SimplifiedFinding(MinimalSerializerMixin, BaseModel):
    """Simplified security finding with only LLM-relevant information."""

    id: str
    uid: str
    status: Literal["FAIL", "PASS", "MANUAL"]
    severity: Literal["critical", "high", "medium", "low", "informational"]
    check_metadata: CheckMetadata
    status_extended: str | None = None
    delta: Literal["new", "changed"] | None = None
    muted: bool | None = None
    muted_reason: str | None = None

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFinding":
        """Transform JSON:API finding response to simplified format."""
        attributes = data["attributes"]
        check_metadata = attributes["check_metadata"]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_metadata=CheckMetadata.from_api_response(check_metadata),
            status_extended=attributes.get("status_extended"),
            delta=attributes.get("delta"),
            muted=attributes.get("muted"),
            muted_reason=attributes.get("muted_reason"),
        )


class DetailedFinding(SimplifiedFinding):
    """Detailed security finding with comprehensive information for deep analysis.

    Extends SimplifiedFinding with temporal metadata and relationships to scans and resources.
    Use this when you need complete context about a specific finding.
    """

    inserted_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    scan_id: str | None = None
    resource_ids: list[str] | None = None

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
        resource_ids = None
        resources_data = relationships.get("resources", {}).get("data", [])
        if resources_data:
            resource_ids = [r["id"] for r in resources_data]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_metadata=CheckMetadata.from_api_response(check_metadata),
            status_extended=attributes.get("status_extended"),
            delta=attributes.get("delta"),
            muted=attributes.get("muted"),
            muted_reason=attributes.get("muted_reason"),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
            first_seen_at=attributes.get("first_seen_at"),
            scan_id=scan_id,
            resource_ids=resource_ids,
        )


class FindingsListResponse(BaseModel):
    """Simplified response for findings list queries."""

    findings: list[SimplifiedFinding]
    total_num_finding: int
    total_num_pages: int
    current_page: int

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

    total: int = 0
    fail: int = 0
    passed: int = 0  # Using 'passed' instead of 'pass' since 'pass' is a Python keyword
    muted: int = 0
    new: int = 0
    changed: int = 0
    fail_new: int = 0
    fail_changed: int = 0
    pass_new: int = 0
    pass_changed: int = 0
    muted_new: int = 0
    muted_changed: int = 0

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
