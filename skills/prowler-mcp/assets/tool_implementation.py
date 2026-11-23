# Example: Tool Implementation (FindingsTools, abridged)
# Source: mcp_server/prowler_mcp_server/prowler_app/tools/findings.py
#
# Key patterns:
# 1. Extend BaseTool; do not override register_tools(). Each public async
#    method becomes the tool prowler_<method_name>.
# 2. search_*/get_*/list_* names are annotated read-only automatically.
# 3. Every parameter uses pydantic Field(default=..., description=...);
#    required IDs use NonBlankStr.
# 4. Validate locally first, build params, run them through build_filter_params().
# 5. Return model.model_dump(); raise on failure, never return an error dict.

from typing import Any, Literal

from pydantic import Field

from prowler_mcp_server.lib.types import NonBlankStr
from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


class FindingsTools(BaseTool):
    """Tools for security findings operations."""

    async def search_security_findings(
        self,
        severity: list[
            Literal["critical", "high", "medium", "low", "informational"]
        ] = Field(
            default=[],
            description="Filter by severity levels. If empty, all severities are returned.",
        ),
        status: list[Literal["FAIL", "PASS", "MANUAL"]] = Field(
            default=["FAIL"],
            description="Filter by finding status. Default: ['FAIL']. Pass [] for all.",
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date (YYYY-MM-DD). Maximum range is 2 days.",
        ),
        date_to: str | None = Field(default=None, description="End date (YYYY-MM-DD)."),
        page_size: int = Field(default=50, description="Results per page"),
        page_number: int = Field(default=1, description="Page number (1-indexed)"),
    ) -> dict[str, Any]:
        """Search security findings. Returns LIGHTWEIGHT findings.

        Without dates it queries the latest scans (most efficient); with dates it
        queries historical findings. Use prowler_get_finding_details with a
        finding 'id' for complete information.
        """
        # Raise InvalidArgument before any request goes out
        self.api_client.validate_page_size(page_size)
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            endpoint = "/findings/latest"
            params = {}
        else:
            endpoint = "/findings"
            params = {
                "filter[inserted_at__gte]": date_range[0],
                "filter[inserted_at__lte]": date_range[1],
            }

        if severity:
            params["filter[severity__in]"] = severity  # list -> CSV below
        if status:
            params["filter[status__in]"] = status
        params["page[size]"] = page_size
        params["page[number]"] = page_number
        # Sparse fieldsets keep the payload small
        params["fields[findings]"] = (
            "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason"
        )

        clean_params = self.api_client.build_filter_params(params)
        api_response = await self.api_client.get(endpoint, params=clean_params)
        return FindingsListResponse.from_api_response(api_response).model_dump()

    async def get_finding_details(
        self,
        finding_id: NonBlankStr = Field(description="UUID of the finding to retrieve."),
    ) -> dict[str, Any]:
        """Retrieve complete details about one finding, including remediation.

        Use this after prowler_search_security_findings.
        """
        params = {"include": "scan,resources"}
        api_response = await self.api_client.get(
            f"/findings/{finding_id}", params=params
        )
        return DetailedFinding.from_api_response(api_response["data"]).model_dump()
