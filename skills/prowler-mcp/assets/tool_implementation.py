# Example: Tool Implementation (FindingsTools)
# Source: mcp_server/prowler_mcp_server/prowler_app/tools/findings.py

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class FindingsTools(BaseTool):
    """
    MCP tools for security findings.

    Key patterns:
    1. Extends BaseTool (no need to override register_tools)
    2. Each async method becomes a tool automatically
    3. Use pydantic.Field() for parameter documentation
    4. Return dict from model_dump() for serialization
    """

    async def search_security_findings(
        self,
        severity: list[
            Literal["critical", "high", "medium", "low", "informational"]
        ] = Field(
            default=[],
            description="Filter by severity levels. Multiple values allowed.",
        ),
        status: list[Literal["FAIL", "PASS", "MANUAL"]] = Field(
            default=["FAIL"],
            description="Filter by finding status. Default: ['FAIL'].",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by cloud provider (aws, azure, gcp, etc.).",
        ),
        page_size: int = Field(
            default=50,
            description="Number of results per page.",
        ),
        page_number: int = Field(
            default=1,
            description="Page number (1-indexed).",
        ),
    ) -> dict[str, Any]:
        """
        Search security findings with rich filtering.

        Returns simplified finding data optimized for LLM consumption.
        """
        # Validate page size
        self.api_client.validate_page_size(page_size)

        # Build query parameters
        params = {
            "page[size]": page_size,
            "page[number]": page_number,
        }
        if severity:
            params["filter[severity__in]"] = ",".join(severity)
        if status:
            params["filter[status__in]"] = ",".join(status)
        if provider_type:
            params["filter[provider_type__in]"] = ",".join(provider_type)

        # Make API request
        api_response = await self.api_client.get("/findings", params=params)

        # Transform to simplified model and return
        simplified_response = FindingsListResponse.from_api_response(api_response)
        return simplified_response.model_dump()

    async def get_finding_details(
        self,
        finding_id: str = Field(
            description="UUID of the finding to retrieve.",
        ),
    ) -> dict[str, Any]:
        """
        Get comprehensive details for a specific finding.

        Returns full finding data including remediation steps.
        """
        params = {"include": "resources,scan"}
        api_response = await self.api_client.get(
            f"/findings/{finding_id}", params=params
        )
        detailed_finding = DetailedFinding.from_api_response(
            api_response.get("data", {})
        )
        return detailed_finding.model_dump()
