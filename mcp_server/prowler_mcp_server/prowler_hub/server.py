"""
Prowler Hub MCP module

Provides access to Prowler Hub API for security checks and compliance frameworks.
"""

from typing import Optional, Any, Literal
import httpx
from fastmcp import FastMCP

# Initialize FastMCP for Prowler Hub
hub_mcp_server = FastMCP("prowler-hub")

# API base URL
BASE_URL = "https://hub.prowler.com/api"

# HTTP client configuration
client = httpx.Client(
    base_url=BASE_URL, timeout=30.0, headers={"Accept": "application/json"}
)


@hub_mcp_server.tool()
async def get_check_filters() -> dict[str, Any]:
    """
    Get available values for filtering for tool `get_checks`. Recommended to use before calling `get_checks` to get the available values for the filters.

    Returns:
        Available filter options including providers, types, services, severities,
        categories, and compliance frameworks with their respective counts
    """
    try:
        response = client.get("/check/filters")
        response.raise_for_status()
        filters = response.json()

        return {"filters": filters}
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


# Security Check Tools
@hub_mcp_server.tool()
async def get_checks(
    providers: Optional[list[str]] = None,
    types: Optional[list[str]] = None,
    services: Optional[list[str]] = None,
    severities: Optional[list[Literal["low", "medium", "high", "critical"]]] = None,
    categories: Optional[list[str]] = None,
    compliances: Optional[list[str]] = None,
    ids: Optional[list[str]] = None,
    fields: Optional[
        list[
            Literal[
                "id",
                "title",
                "description",
                "provider",
                "type",
                "service",
                "subservice",
                "severity",
                "risk",
                "reference",
                "remediation",
                "services_required",
                "aws_arn_template",
                "notes",
                "categories",
                "default_value",
                "resource_type",
                "related_url",
                "depends_on",
                "related_to",
                "fixer",
            ]
        ]
    ] = ["id", "title", "description"],
) -> dict[str, Any]:
    """
    List security Prowler Checks. The list can be filtered by the parameters defined for the tool.
    It is recommended to use the tool `get_check_filters` to get the available values for the filters.
    A not filtered request will return more than 1000 checks, so it is recommended to use the filters.

    Args:
        providers: Filter by Prowler provider IDs. Example: ["aws", "azure"]. Use the tool `list_providers` to get the available providers IDs.
        types: Filter by check types.
        services: Filter by provider services IDs. Example: ["s3", "keyvault"]. Use the tool `list_providers` to get the available services IDs in a provider.
        severities: Filter by severity levels. Example: ["medium", "high"].
        categories: Filter by categories. Example: ["cluster-security", "encryption"].
        compliances: Filter by compliance framework IDs. Example: ["cis_4.0_aws", "ens_rd2022_azure"].
        ids: Filter by specific check IDs. Example: ["s3_bucket_level_public_access_block"].
        fields: Specify which fields from checks metadata to return (id is always included). Example: ["id", "title", "description", "risk"].

    Returns:
        List of security checks matching the filters. The structure is as follows:
        {
            "count": N,
            "checks": [
                {"id": "check_id_1", "title": "check_title_1", "description": "check_description_1", ...},
                {"id": "check_id_2", "title": "check_title_2", "description": "check_description_2", ...},
                {"id": "check_id_3", "title": "check_title_3", "description": "check_description_3", ...},
                ...
            ]
        }
    """
    params: dict[str, str] = {}

    if providers:
        params["providers"] = ",".join(providers)
    if types:
        params["types"] = ",".join(types)
    if services:
        params["services"] = ",".join(services)
    if severities:
        params["severities"] = ",".join(severities)
    if categories:
        params["categories"] = ",".join(categories)
    if compliances:
        params["compliances"] = ",".join(compliances)
    if ids:
        params["ids"] = ",".join(ids)
    if fields:
        params["fields"] = ",".join(fields)

    try:
        response = client.get("/check", params=params)
        response.raise_for_status()
        checks = response.json()

        checks_dict = {}
        for check in checks:
            check_data = {}
            # Always include the id field as it's mandatory for the response structure
            if "id" in check:
                check_data["id"] = check["id"]

            # Include other requested fields
            for field in fields:
                if field != "id" and field in check:  # Skip id since it's already added
                    check_data[field] = check[field]
            checks_dict[check["id"]] = check_data

        return {"count": len(checks), "checks": checks_dict}
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


@hub_mcp_server.tool()
async def search_checks(term: str) -> dict[str, Any]:
    """
    Search the term across all text properties of check metadata.

    Args:
        term: Search term to find in check titles, descriptions, and other text fields

    Returns:
        List of checks matching the search term
    """
    try:
        response = client.get("/check/search", params={"term": term})
        response.raise_for_status()
        checks = response.json()

        return {
            "count": len(checks),
            "checks": checks,
        }
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


# Compliance Framework Tools
@hub_mcp_server.tool()
async def get_compliance_frameworks(
    provider: Optional[list[str]] = None,
    fields: Optional[
        list[
            Literal[
                "id",
                "framework",
                "provider",
                "description",
                "requirements",
                "version",
                "total_checks",
                "total_requirements",
                "created_at",
                "updated_at",
            ]
        ]
    ] = [
        "id",
        "framework",
        "provider",
        "description",
        "total_checks",
        "total_requirements",
    ],
) -> dict[str, Any]:
    """
    List and filter compliance frameworks. The list can be filtered by the parameters defined for the tool.

    Args:
        provider: Filter by Prowler provider IDs. Example: ["aws", "azure", "gcp"]. Use the tool `list_providers` to get the available providers IDs.
        fields: Specify which fields to return (id is always included). Example: ["id", "provider", "description", "version"].
                It is recommended to run with the default parameters because the full response is too large.

    Returns:
        List of compliance frameworks. The structure is as follows:
        {
            "count": N,
            "frameworks": {
                "framework_id": {
                    "id": "framework_id",
                    "provider": "provider_id",
                    "description": "framework_description",
                    "version": "framework_version"
                }
            }
        }
    """
    params = {}

    if provider:
        params["provider"] = ",".join(provider)
    if fields:
        params["fields"] = ",".join(fields)

    try:
        response = client.get("/compliance", params=params)
        response.raise_for_status()
        frameworks = response.json()

        frameworks_dict = {}
        for framework in frameworks:
            framework_data = {}
            # Always include the id field as it's mandatory for the response structure
            if "id" in framework:
                framework_data["id"] = framework["id"]

            # Include other requested fields
            for field in fields:
                if (
                    field != "id" and field in framework
                ):  # Skip id since it's already added
                    framework_data[field] = framework[field]
            frameworks_dict[framework["id"]] = framework_data

        return {"count": len(frameworks), "frameworks": frameworks_dict}
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


@hub_mcp_server.tool()
async def search_compliance_frameworks(term: str) -> dict[str, Any]:
    """
    Search compliance frameworks by term.

    Args:
        term: Search term to find in framework names and descriptions

    Returns:
        List of compliance frameworks matching the search term
    """
    try:
        response = client.get("/compliance/search", params={"term": term})
        response.raise_for_status()
        frameworks = response.json()

        return {
            "count": len(frameworks),
            "search_term": term,
            "frameworks": frameworks,
        }
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


# Provider Tools
@hub_mcp_server.tool()
async def list_providers() -> dict[str, Any]:
    """
    Get all available Prowler providers and their associated services.

    Returns:
        List of Prowler providers with their associated services. The structure is as follows:
        {
            "count": N,
            "providers": {
                "provider_id": {
                    "name": "provider_name",
                    "services": ["service_id_1", "service_id_2", "service_id_3", ...]
                }
            }
        }
    """
    try:
        response = client.get("/providers")
        response.raise_for_status()
        providers = response.json()

        providers_dict = {}
        for provider in providers:
            providers_dict[provider["id"]] = {
                "name": provider.get("name", ""),
                "services": provider.get("services", []),
            }

        return {"count": len(providers), "providers": providers_dict}
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}


# Analytics Tools
@hub_mcp_server.tool()
async def get_artifacts_count() -> dict[str, Any]:
    """
    Get total count of security artifacts (checks + compliance frameworks).

    Returns:
        Total number of artifacts in the Prowler Hub.
    """
    try:
        response = client.get("/n_artifacts")
        response.raise_for_status()
        data = response.json()

        return {
            "total_artifacts": data.get("n", 0),
            "details": "Total count includes both security checks and compliance frameworks",
        }
    except httpx.HTTPStatusError as e:
        return {
            "error": f"HTTP error {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"error": str(e)}
