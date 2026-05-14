# Example: MCP Models with MinimalSerializerMixin
# Source: mcp_server/prowler_mcp_server/prowler_app/models/

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)


class MinimalSerializerMixin(BaseModel):
    """
    Mixin that excludes empty values from serialization.

    Key pattern: Reduces token usage by removing None, empty strings, empty lists/dicts.
    Use this for all LLM-facing models.
    """

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)
        return {k: v for k, v in data.items() if not self._should_exclude(k, v)}

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Override in subclasses for custom exclusion logic."""
        if value is None:
            return True
        if value == "":
            return True
        if isinstance(value, list) and not value:
            return True
        if isinstance(value, dict) and not value:
            return True
        return False


class CheckRemediation(MinimalSerializerMixin, BaseModel):
    """Remediation information - uses mixin to strip empty fields."""

    model_config = ConfigDict(frozen=True)

    cli: str | None = Field(default=None, description="CLI command for remediation")
    terraform: str | None = Field(default=None, description="Terraform code")
    other: str | None = Field(default=None, description="Other remediation steps")
    recommendation: str | None = Field(
        default=None, description="Best practice recommendation"
    )


class SimplifiedFinding(MinimalSerializerMixin, BaseModel):
    """
    Lightweight finding for list responses.

    Key pattern: Two-tier serialization
    - SimplifiedFinding: minimal fields for lists (fast, low tokens)
    - DetailedFinding: full fields for single item (complete info)
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Finding UUID")
    uid: str = Field(description="Unique finding identifier")
    status: Literal["FAIL", "PASS", "MANUAL"] = Field(description="Finding status")
    severity: str = Field(description="Severity level")
    check_id: str = Field(description="Check ID that generated this finding")
    resource_name: str | None = Field(default=None, description="Affected resource")

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFinding":
        """Transform JSON:API response to model."""
        attributes = data["attributes"]
        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_id=attributes["check_id"],
            resource_name=attributes.get("resource_name"),
        )


class DetailedFinding(SimplifiedFinding):
    """
    Full finding details - extends SimplifiedFinding.

    Key pattern: Inheritance for two-tier serialization.
    """

    status_extended: str = Field(description="Detailed status message")
    region: str | None = Field(default=None, description="Cloud region")
    remediation: CheckRemediation | None = Field(default=None, description="How to fix")

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedFinding":
        """Transform JSON:API response to detailed model."""
        attributes = data["attributes"]
        check_metadata = attributes.get("check_metadata", {})
        remediation_data = check_metadata.get("Remediation", {})

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_id=attributes["check_id"],
            resource_name=attributes.get("resource_name"),
            status_extended=attributes.get("status_extended", ""),
            region=attributes.get("region"),
            remediation=(
                CheckRemediation(
                    cli=remediation_data.get("Code", {}).get("CLI"),
                    terraform=remediation_data.get("Code", {}).get("Terraform"),
                    recommendation=remediation_data.get("Recommendation", {}).get(
                        "Text"
                    ),
                )
                if remediation_data
                else None
            ),
        )


class FindingsListResponse(BaseModel):
    """Wrapper for list responses with pagination."""

    findings: list[SimplifiedFinding]
    total: int
    page: int
    page_size: int

    @classmethod
    def from_api_response(cls, data: dict) -> "FindingsListResponse":
        findings = [
            SimplifiedFinding.from_api_response(f) for f in data.get("data", [])
        ]
        meta = data.get("meta", {}).get("pagination", {})
        return cls(
            findings=findings,
            total=meta.get("count", len(findings)),
            page=meta.get("page", 1),
            page_size=meta.get("page_size", len(findings)),
        )
