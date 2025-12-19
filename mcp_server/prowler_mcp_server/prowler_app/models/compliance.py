"""Pydantic models for simplified compliance responses."""

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)


class ComplianceRequirementAttribute(MinimalSerializerMixin, BaseModel):
    """Requirement attributes including associated check IDs.

    Used to map requirements to the checks that validate them.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Requirement identifier within the framework (e.g., '1.1', '2.1.1')"
    )
    name: str = Field(default="", description="Human-readable name of the requirement")
    description: str = Field(
        default="", description="Detailed description of the requirement"
    )
    check_ids: list[str] = Field(
        default_factory=list,
        description="List of Prowler check IDs that validate this requirement",
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "ComplianceRequirementAttribute":
        """Transform JSON:API compliance requirement attributes response to simplified format."""
        attributes = data.get("attributes", {})

        # Extract check_ids from the nested attributes structure
        nested_attributes = attributes.get("attributes", {})
        check_ids = nested_attributes.get("check_ids", [])

        return cls(
            id=attributes.get("id", data.get("id", "")),
            name=attributes.get("name", ""),
            description=attributes.get("description", ""),
            check_ids=check_ids if check_ids else [],
        )


class ComplianceRequirementAttributesListResponse(BaseModel):
    """Response for compliance requirement attributes list with check_ids mappings."""

    model_config = ConfigDict(frozen=True)

    requirements: list[ComplianceRequirementAttribute] = Field(
        description="List of requirements with their associated check IDs"
    )
    total_count: int = Field(description="Total number of requirements")

    @classmethod
    def from_api_response(
        cls, response: dict
    ) -> "ComplianceRequirementAttributesListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])

        requirements = [
            ComplianceRequirementAttribute.from_api_response(item) for item in data
        ]

        return cls(
            requirements=requirements,
            total_count=len(requirements),
        )


class ComplianceFrameworkSummary(MinimalSerializerMixin, BaseModel):
    """Simplified compliance framework overview for list operations.

    Used by get_compliance_overview() to show high-level compliance status
    per framework.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique identifier for this compliance overview entry")
    compliance_id: str = Field(
        description="Compliance framework identifier (e.g., 'cis_1.5_aws', 'pci_dss_v4.0_aws')"
    )
    framework: str = Field(
        description="Human-readable framework name (e.g., 'CIS', 'PCI-DSS', 'HIPAA')"
    )
    version: str = Field(description="Framework version (e.g., '1.5', '4.0')")
    total_requirements: int = Field(
        default=0, description="Total number of requirements in this framework"
    )
    requirements_passed: int = Field(
        default=0, description="Number of requirements that passed"
    )
    requirements_failed: int = Field(
        default=0, description="Number of requirements that failed"
    )
    requirements_manual: int = Field(
        default=0, description="Number of requirements requiring manual verification"
    )

    @property
    def pass_percentage(self) -> float:
        """Calculate pass percentage based on passed requirements."""
        if self.total_requirements == 0:
            return 0.0
        return round((self.requirements_passed / self.total_requirements) * 100, 1)

    @property
    def fail_percentage(self) -> float:
        """Calculate fail percentage based on failed requirements."""
        if self.total_requirements == 0:
            return 0.0
        return round((self.requirements_failed / self.total_requirements) * 100, 1)

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Serialize with calculated percentages included."""
        data = handler(self)
        # Filter out None/empty values
        data = {k: v for k, v in data.items() if v is not None and v != "" and v != []}
        # Add calculated percentages
        data["pass_percentage"] = self.pass_percentage
        data["fail_percentage"] = self.fail_percentage
        return data

    @classmethod
    def from_api_response(cls, data: dict) -> "ComplianceFrameworkSummary":
        """Transform JSON:API compliance overview response to simplified format."""
        attributes = data.get("attributes", {})

        # The compliance_id field may be in attributes or use the "id" field from attributes
        compliance_id = attributes.get("id", data.get("id", ""))

        return cls(
            id=data["id"],
            compliance_id=compliance_id,
            framework=attributes.get("framework", ""),
            version=attributes.get("version", ""),
            total_requirements=attributes.get("total_requirements", 0),
            requirements_passed=attributes.get("requirements_passed", 0),
            requirements_failed=attributes.get("requirements_failed", 0),
            requirements_manual=attributes.get("requirements_manual", 0),
        )


class ComplianceRequirement(MinimalSerializerMixin, BaseModel):
    """Individual compliance requirement with its status.

    Used by get_compliance_framework_state_details() to show requirement-level breakdown.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Requirement identifier within the framework (e.g., '1.1', '2.1.1')"
    )
    description: str = Field(
        description="Human-readable description of the requirement"
    )
    status: Literal["FAIL", "PASS", "MANUAL"] = Field(
        description="Requirement status: FAIL (not compliant), PASS (compliant), MANUAL (requires manual verification)"
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "ComplianceRequirement":
        """Transform JSON:API compliance requirement response to simplified format."""
        attributes = data.get("attributes", {})

        return cls(
            id=attributes.get("id", data.get("id", "")),
            description=attributes.get("description", ""),
            status=attributes.get("status", "MANUAL"),
        )


class ComplianceFrameworksListResponse(BaseModel):
    """Response for compliance frameworks list with aggregated statistics."""

    model_config = ConfigDict(frozen=True)

    frameworks: list[ComplianceFrameworkSummary] = Field(
        description="List of compliance frameworks with their status"
    )
    total_count: int = Field(description="Total number of frameworks returned")

    @classmethod
    def from_api_response(cls, response: dict) -> "ComplianceFrameworksListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])

        frameworks = [
            ComplianceFrameworkSummary.from_api_response(item) for item in data
        ]

        return cls(
            frameworks=frameworks,
            total_count=len(frameworks),
        )


class ComplianceRequirementsListResponse(BaseModel):
    """Response for compliance requirements list queries."""

    model_config = ConfigDict(frozen=True)

    requirements: list[ComplianceRequirement] = Field(
        description="List of requirements with their status"
    )
    total_count: int = Field(description="Total number of requirements")
    passed_count: int = Field(description="Number of requirements with PASS status")
    failed_count: int = Field(description="Number of requirements with FAIL status")
    manual_count: int = Field(description="Number of requirements with MANUAL status")

    @classmethod
    def from_api_response(cls, response: dict) -> "ComplianceRequirementsListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])

        requirements = [ComplianceRequirement.from_api_response(item) for item in data]

        # Calculate counts
        passed = sum(1 for r in requirements if r.status == "PASS")
        failed = sum(1 for r in requirements if r.status == "FAIL")
        manual = sum(1 for r in requirements if r.status == "MANUAL")

        return cls(
            requirements=requirements,
            total_count=len(requirements),
            passed_count=passed,
            failed_count=failed,
            manual_count=manual,
        )
