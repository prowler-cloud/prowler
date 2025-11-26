"""Pydantic models for simplified compliance responses."""

from pydantic import BaseModel, model_serializer


class ComplianceFramework(BaseModel):
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
    def _serialize(self, serializer, info):
        """Exclude None and empty string fields, and add calculated pass_percentage."""
        data = serializer(self)
        # Filter out None and empty strings
        filtered = {k: v for k, v in data.items() if v is not None and v != ""}
        # Add calculated pass_percentage
        filtered["pass_percentage"] = self.pass_percentage
        return filtered

    @classmethod
    def from_api_response(cls, data: dict) -> "ComplianceFramework":
        """Transform JSON:API compliance overview response to simplified format."""
        attributes = data.get("attributes", {})

        return cls(
            id=data.get("id"),
            compliance_id=attributes.get("compliance_id") or None,
            framework=attributes.get("framework") or None,
            version=attributes.get("version") or None,
            provider=attributes.get("provider") or None,
            region=attributes.get("region") or None,
            total_requirements=attributes.get("total_requirements", 0),
            requirements_passed=attributes.get("requirements_passed", 0),
            requirements_failed=attributes.get("requirements_failed", 0),
            requirements_manual=attributes.get("requirements_manual", 0),
        )


class ComplianceFrameworksListResponse(BaseModel):
    """Simplified response for compliance frameworks list queries."""

    frameworks: list[ComplianceFramework]
    total_count: int = 0
    page_number: int = 1
    page_size: int = 100
    has_next: bool = False
    has_prev: bool = False

    @classmethod
    def from_api_response(cls, response: dict) -> "ComplianceFrameworksListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])
        links = response.get("links", {})
        meta = response.get("meta", {})

        frameworks = [ComplianceFramework.from_api_response(item) for item in data]

        return cls(
            frameworks=frameworks,
            total_count=meta.get("total", len(frameworks)),
            page_number=meta.get("page", {}).get("number", 1),
            page_size=meta.get("page", {}).get("size", 100),
            has_next=links.get("next") is not None,
            has_prev=links.get("prev") is not None,
        )
