"""Pydantic models for simplified compliance responses."""

from typing import Any

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel, SerializerFunctionWrapHandler, model_serializer


class ComplianceFramework(MinimalSerializerMixin, BaseModel):
    """Simplified compliance framework overview."""

    id: str
    compliance_id: str | None = None
    framework: str | None = None
    version: str | None = None
    provider: str | None = None
    region: str | None = None
    total_requirements: int = 0
    requirements_passed: int = 0
    requirements_failed: int = 0
    requirements_manual: int = 0

    @property
    def pass_percentage(self) -> float:
        """Calculate pass percentage based on passed requirements."""
        if self.total_requirements == 0:
            return 0.0
        return round((self.requirements_passed / self.total_requirements) * 100, 2)

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Exclude None and empty string fields, and add calculated pass_percentage."""
        # Use parent's exclusion logic
        data = super()._serialize(handler)
        # Add calculated pass_percentage
        data["pass_percentage"] = self.pass_percentage
        return data

    @classmethod
    def from_api_response(cls, data: dict) -> "ComplianceFramework":
        """Transform JSON:API compliance overview response to simplified format."""
        attributes = data["attributes"]

        return cls(
            id=data["id"],
            compliance_id=attributes.get("compliance_id"),
            framework=attributes.get("framework"),
            version=attributes.get("version"),
            provider=attributes.get("provider"),
            region=attributes.get("region"),
            total_requirements=attributes["total_requirements"],
            requirements_passed=attributes["requirements_passed"],
            requirements_failed=attributes["requirements_failed"],
            requirements_manual=attributes["requirements_manual"],
        )


class ComplianceFrameworksListResponse(BaseModel):
    """Simplified response for compliance frameworks list queries."""

    frameworks: list[ComplianceFramework]
    total_count: int

    @classmethod
    def from_api_response(cls, response: dict) -> "ComplianceFrameworksListResponse":
        """Transform JSON:API response to simplified format."""
        data = response["data"]

        frameworks = [ComplianceFramework.from_api_response(item) for item in data]

        return cls(
            frameworks=frameworks,
            total_count=len(frameworks),
        )
