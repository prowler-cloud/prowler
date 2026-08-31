"""
Prowler Hub MCP module

Provides access to Prowler Hub API for security checks and compliance frameworks.
"""

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from prowler_mcp_server import __version__
from prowler_mcp_server.lib.errors import (
    UpstreamInvalidResponse,
    parse_json_response,
)
from prowler_mcp_server.lib.types import NonBlankStr
from prowler_mcp_server.lib.urls import url_path

# Initialize FastMCP for Prowler Hub
hub_mcp_server = FastMCP("prowler-hub", mask_error_details=True)

# API base URL
BASE_URL = "https://hub.prowler.com/api"

# HTTP client configuration
prowler_hub_client = httpx.Client(
    base_url=BASE_URL,
    timeout=30.0,
    headers={
        "Accept": "application/json",
        "User-Agent": f"prowler-mcp-server/{__version__}",
    },
)

# Sentences for the not-found cases. They are authored here, and raised as a
# ToolError without a `from` clause, because they name the resource the caller
# asked for and the next tool to reach for -- neither of which the shared
# classifier in lib/errors.py can know.
_CHECK_NOT_FOUND = (
    "No check with the ID '{check_id}' exists in Prowler Hub. Use "
    "prowler_hub_semantic_search_checks to find the right ID."
)
_COMPLIANCE_NOT_FOUND = (
    "No compliance framework with the ID '{compliance_id}' exists in Prowler Hub. "
    "Use prowler_hub_semantic_search_compliances to find the right ID."
)

# GitHub raw content base URL for Prowler checks
GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/"
    "prowler/providers"
)

# Separate HTTP client for GitHub raw content
github_raw_client = httpx.Client(
    timeout=30.0,
    headers={
        "Accept": "*/*",
        "User-Agent": f"prowler-mcp-server/{__version__}",
    },
)


def _get_hub_endpoint(
    *path_segments: str, params: dict[str, str] | None = None
) -> httpx.Response:
    """GET a Prowler Hub endpoint, named as one argument per path segment.

    Args:
        *path_segments: The endpoint path segments, in order.
        params: Query parameters for the request.

    Returns:
        The response unread, so a caller can tell a 404 from a failed request.
    """
    return prowler_hub_client.get(url_path(*path_segments), params=params)


def github_check_path(provider_id: str, check_id: str, suffix: str) -> str:
    """Build the GitHub raw URL for a given check artifact suffix using provider
    and check_id.

    Suffix examples: ".metadata.json", ".py", "_fixer.py"
    """
    try:
        service_id = check_id.split("_", 1)[0]
    except IndexError:
        service_id = check_id
    path = url_path(provider_id, "services", service_id, check_id, check_id)
    return f"{GITHUB_RAW_BASE}{path}{suffix}"


def _hub_provider_for_check(check_id: str) -> str | None:
    """Ask Prowler Hub which provider it lists a check under.

    Args:
        check_id: Check ID the caller asked for

    Returns:
        The provider the Hub lists the check under, or None when the Hub knows
        no such check.

    Raises:
        httpx.HTTPError: The Hub could not be reached.
        UpstreamInvalidResponse: The Hub answered with a body that is not JSON.
        ValueError: The Hub answered with something that names no provider.
    """
    response = _get_hub_endpoint("check", check_id)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    check = parse_json_response(response)

    # An empty body is how the Hub reports an unknown ID on some routes, so it
    # is read the same way get_check_details reads it: no such check.
    if not isinstance(check, dict) or not check:
        return None

    provider = check.get("provider")
    if isinstance(provider, str) and provider.strip():
        return provider
    # A check the Hub returned without a provider tells us nothing about the
    # provider the caller asked for, so it counts as unanswered rather than as
    # a check that does not exist.
    raise ValueError(f"Prowler Hub listed check '{check_id}' without a provider")


def _explain_missing_check_file(
    provider_id: str,
    check_id: str,
    *,
    when_check_belongs_here: str,
    when_unverified: str,
) -> str:
    """Explain a 404 from GitHub for one of a check's source files.

    GitHub answers 404 to three different mistakes, an ID that exists nowhere,
    an ID that exists under a different provider, and an ID that exists right
    here whose file is simply absent, and cannot tell them apart. Prowler Hub
    can, so it is asked before anything is claimed about the ID.

    Args:
        provider_id: Provider the caller asked for
        check_id: Check the caller asked for
        when_check_belongs_here: Message for the case where the Hub confirms the
            check does belong to this provider
        when_unverified: Message for the case where the Hub could not be asked

    Returns:
        The sentence to fail the tool with
    """
    try:
        hub_provider = _hub_provider_for_check(check_id)
    except (httpx.HTTPError, UpstreamInvalidResponse, ValueError):
        return when_unverified

    if hub_provider is None:
        return _CHECK_NOT_FOUND.format(check_id=check_id)
    if hub_provider != provider_id:
        return (
            f"Provider '{provider_id}' has no check '{check_id}'. Prowler Hub lists "
            f"that check under provider '{hub_provider}', so retry with "
            f"provider_id='{hub_provider}'."
        )
    return when_check_belongs_here


# Security Check Tools
@hub_mcp_server.tool()
async def list_checks(
    providers: list[str] = Field(
        default=[],
        description="Filter by Prowler provider IDs. Example: ['aws', 'azure']. Use `prowler_hub_list_providers` to get available provider IDs.",
    ),
    services: list[str] = Field(
        default=[],
        description="Filter by provider services. Example: ['s3', 'ec2', 'keyvault']. Use `prowler_hub_get_provider_services` to get available services for a provider.",
    ),
    severities: list[str] = Field(
        default=[],
        description="Filter by severity levels. Example: ['high', 'critical']. Available: 'low', 'medium', 'high', 'critical'.",
    ),
    categories: list[str] = Field(
        default=[],
        description="Filter by security categories. Example: ['encryption', 'internet-exposed'].",
    ),
    compliances: list[str] = Field(
        default=[],
        description="Filter by compliance framework IDs. Example: ['cis_4.0_aws', 'ens_rd2022_azure']. Use `prowler_hub_list_compliances` to get available compliance IDs.",
    ),
) -> dict:
    """List security Prowler Checks with filtering capabilities.

    IMPORTANT: This tool returns LIGHTWEIGHT check data. Use this for fast browsing and filtering.
    For complete details including risk, remediation guidance, and categories use `prowler_hub_get_check_details`.

    IMPORTANT: An unfiltered request returns 1000+ checks. Use filters to narrow results.

    Returns:
        {
            "count": N,
            "checks": [
                {
                    "id": "check_id",
                    "provider": "provider_id",
                    "title": "Human-readable check title",
                    "severity": "critical|high|medium|low",
                },
                ...
            ]
        }

    Useful Example Workflow:
    1. Use `prowler_hub_list_providers` to see available Prowler providers
    2. Use `prowler_hub_get_provider_services` to see services for a provider
    3. Use this tool with filters to find relevant checks
    4. Use `prowler_hub_get_check_details` to get complete information for a specific check
    """
    # Lightweight fields for listing
    lightweight_fields = "id,title,severity,provider"

    params: dict[str, str] = {"fields": lightweight_fields}

    if providers:
        params["providers"] = ",".join(providers)
    if services:
        params["services"] = ",".join(services)
    if severities:
        params["severities"] = ",".join(severities)
    if categories:
        params["categories"] = ",".join(categories)
    if compliances:
        params["compliances"] = ",".join(compliances)

    response = _get_hub_endpoint("check", params=params)
    response.raise_for_status()
    checks = parse_json_response(response)

    # Return checks as a lightweight list
    checks_list = []
    for check in checks:
        check_data = {
            "id": check["id"],
            "provider": check["provider"],
            "title": check["title"],
            "severity": check["severity"],
        }
        checks_list.append(check_data)

    return {"count": len(checks), "checks": checks_list}


@hub_mcp_server.tool()
async def semantic_search_checks(
    term: NonBlankStr = Field(
        description="Search term. Examples: 'public access', 'encryption', 'MFA', 'logging'.",
    ),
) -> dict:
    """Search for security checks using free-text search across all metadata.

    IMPORTANT: This tool returns LIGHTWEIGHT check data. Use this for discovering checks by topic.
    For complete details including risk, remediation guidance, and categories use `prowler_hub_get_check_details`.

    Searches across check titles, descriptions, risk statements, remediation guidance,
    and other text fields. Use this when you don't know the exact check ID or want to
    explore checks related to a topic.

    Returns:
        {
            "count": N,
            "checks": [
                {
                    "id": "check_id",
                    "provider": "provider_id",
                    "title": "Human-readable check title",
                    "severity": "critical|high|medium|low",
                },
                ...
            ]
        }

    Useful Example Workflow:
    1. Use this tool to search for checks by keyword or topic
    2. Use `prowler_hub_list_checks` with filters for more targeted browsing
    3. Use `prowler_hub_get_check_details` to get complete information for a specific check
    """
    response = _get_hub_endpoint("check", "search", params={"term": term})
    response.raise_for_status()
    checks = parse_json_response(response)

    # Return checks as a lightweight list
    checks_list = []
    for check in checks:
        check_data = {
            "id": check["id"],
            "provider": check["provider"],
            "title": check["title"],
            "severity": check["severity"],
        }
        checks_list.append(check_data)

    return {"count": len(checks), "checks": checks_list}


@hub_mcp_server.tool()
async def get_check_details(
    check_id: NonBlankStr = Field(
        description="The check ID to retrieve details for. Example: 's3_bucket_level_public_access_block'"
    ),
) -> dict:
    """Retrieve comprehensive details about a specific security check by its ID.

    IMPORTANT: This tool returns COMPLETE check details.
    Use this after finding a specific check ID, you can get it via `prowler_hub_list_checks` or `prowler_hub_semantic_search_checks`.

    Returns:
        {
          "id": "string",
          "title": "string",
          "description": "string",
          "provider": "string",
          "service": "string",
          "severity": "low",
          "risk": "string",
          "reference": [
            "string"
          ],
          "additional_urls": [
            "string"
          ],
          "remediation": {
            "cli": {
              "description": "string"
            },
            "terraform": {
              "description": "string"
            },
            "nativeiac": {
              "description": "string"
            },
            "other": {
              "description": "string"
            },
            "wui": {
              "description": "string",
              "reference": "string"
            }
          },
          "services_required": [
            "string"
          ],
          "notes": "string",
          "compliances": [
            {
              "name": "string",
              "id": "string"
            }
          ],
          "categories": [
            "string"
          ],
          "resource_type": "string",
          "related_url": "string",
          "fixer": bool
        }

    Useful Example Workflow:
    1. Use `prowler_hub_list_checks` or `prowler_hub_search_checks` to find check IDs
    2. Use this tool with the check 'id' to get complete information including remediation guidance
    """
    try:
        response = _get_hub_endpoint("check", check_id)
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # No `from`: this names the check, which the shared classifier cannot.
            raise ToolError(_CHECK_NOT_FOUND.format(check_id=check_id))
        raise

    check = parse_json_response(response)

    if not check:
        raise ToolError(_CHECK_NOT_FOUND.format(check_id=check_id))

    # Build response with only non-empty fields to save tokens
    result = {}

    # Core fields
    result["id"] = check["id"]
    if check.get("title"):
        result["title"] = check["title"]
    if check.get("description"):
        result["description"] = check["description"]
    if check.get("provider"):
        result["provider"] = check["provider"]
    if check.get("service"):
        result["service"] = check["service"]
    if check.get("severity"):
        result["severity"] = check["severity"]
    if check.get("risk"):
        result["risk"] = check["risk"]
    if check.get("resource_type"):
        result["resource_type"] = check["resource_type"]

    # List fields
    if check.get("reference"):
        result["reference"] = check["reference"]
    if check.get("additional_urls"):
        result["additional_urls"] = check["additional_urls"]
    if check.get("services_required"):
        result["services_required"] = check["services_required"]
    if check.get("categories"):
        result["categories"] = check["categories"]
    if check.get("compliances"):
        result["compliances"] = check["compliances"]

    # Other fields
    if check.get("notes"):
        result["notes"] = check["notes"]
    if check.get("related_url"):
        result["related_url"] = check["related_url"]
    if check.get("fixer") is not None:
        result["fixer"] = check["fixer"]

    # Remediation - filter out empty nested values
    remediation = check.get("remediation", {})
    if remediation:
        filtered_remediation = {}
        for key, value in remediation.items():
            if value and isinstance(value, dict):
                # Filter out empty values within nested dict
                filtered_value = {k: v for k, v in value.items() if v}
                if filtered_value:
                    filtered_remediation[key] = filtered_value
            elif value:
                filtered_remediation[key] = value
        if filtered_remediation:
            result["remediation"] = filtered_remediation

    return result


@hub_mcp_server.tool()
async def get_check_code(
    provider_id: NonBlankStr = Field(
        description="Prowler Provider ID. Example: 'aws', 'azure', 'gcp', 'kubernetes'. Use `prowler_hub_list_providers` to get available provider IDs.",
    ),
    check_id: NonBlankStr = Field(
        description="The check ID. Example: 's3_bucket_public_access'. Get IDs from `prowler_hub_list_checks` or `prowler_hub_search_checks`.",
    ),
) -> dict:
    """Fetch the Python implementation code of a Prowler security check.

    The check code shows exactly how Prowler evaluates resources for security issues.
    Use this to understand check logic, customize checks, or create new ones.

    Returns:
        {
            "content": "Python source code of the check implementation"
        }
    """
    url = github_check_path(provider_id, check_id, ".py")
    try:
        resp = github_raw_client.get(url)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # No `from`: this names the check and the provider that does have
            # it, neither of which the shared classifier in lib/errors.py knows.
            raise ToolError(
                _explain_missing_check_file(
                    provider_id,
                    check_id,
                    when_check_belongs_here=(
                        f"Prowler Hub lists check '{check_id}' under provider "
                        f"'{provider_id}', but prowler-cloud/prowler has no source file "
                        "for it on the master branch. The check may have been renamed or "
                        "moved since the Hub last indexed it."
                    ),
                    when_unverified=(
                        f"Provider '{provider_id}' has no check '{check_id}' in "
                        "prowler-cloud/prowler, and Prowler Hub could not be asked which "
                        "provider does. Either the ID is wrong or the check belongs to "
                        "another provider, prowler_hub_get_check_details reports the "
                        "provider a check belongs to."
                    ),
                )
            )
        raise

    return {
        "content": resp.text,
    }


@hub_mcp_server.tool()
async def get_check_fixer(
    provider_id: NonBlankStr = Field(
        description="Prowler Provider ID. Example: 'aws', 'azure', 'gcp', 'kubernetes'. Use `prowler_hub_list_providers` to get available provider IDs.",
    ),
    check_id: NonBlankStr = Field(
        description="The check ID. Example: 's3_bucket_public_access'. Get IDs from `prowler_hub_list_checks` or `prowler_hub_search_checks`.",
    ),
) -> dict:
    """Fetch the auto-remediation (fixer) code for a Prowler security check.

    IMPORTANT: Not all checks have fixers. A check with no auto-remediation code fails
    with a message saying so - this is normal for many checks and not a problem to
    report or retry.

    Fixer code provides automated remediation that can fix security issues detected by checks.
    Use this to understand how to programmatically remediate findings.

    Returns:
        {
            "content": "Python source code of the auto-remediation implementation"
        }
    """
    url = github_check_path(provider_id, check_id, "_fixer.py")
    try:
        resp = github_raw_client.get(url)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # "No fixer" is only one of the reasons the file is missing, and the
            # others are the caller's to fix, so they are told apart first.
            raise ToolError(
                _explain_missing_check_file(
                    provider_id,
                    check_id,
                    when_check_belongs_here=(
                        f"Check {check_id} has no auto-remediation code. Many checks do "
                        "not, and that is normal."
                    ),
                    when_unverified=(
                        f"Provider '{provider_id}' has no auto-remediation code for "
                        f"check '{check_id}'. Many checks have none, and that is normal, "
                        f"but Prowler Hub could not be asked whether the check belongs "
                        f"to '{provider_id}' at all. Confirm it with "
                        "prowler_hub_get_check_details if you expected a fixer."
                    ),
                )
            )
        raise

    return {
        "content": resp.text,
    }


# Compliance Framework Tools
@hub_mcp_server.tool()
async def list_compliances(
    provider: list[str] = Field(
        default=[],
        description="Filter by cloud provider. Example: ['aws']. Use `prowler_hub_list_providers` to get available provider IDs.",
    ),
) -> dict:
    """List compliance frameworks supported by Prowler.

    IMPORTANT: This tool returns LIGHTWEIGHT compliance data. Use this for fast browsing and filtering.
    For complete details including requirements use `prowler_hub_get_compliance_details`.

    Compliance frameworks define sets of security requirements that checks map to.
    Use this to discover available frameworks for compliance reporting.

    WARNING: An unfiltered request may return a large number of frameworks. Use the provider with not more than 3 different providers to make easier the response handling.

    Returns:
        {
            "count": N,
            "compliances": [
                {
                    "id": "cis_4.0_aws",
                    "name": "CIS Amazon Web Services Foundations Benchmark v4.0",
                    "provider": "aws",
                },
                ...
            ]
        }

    Useful Example Workflow:
    1. Use `prowler_hub_list_providers` to see available cloud providers
    2. Use this tool to browse compliance frameworks
    3. Use `prowler_hub_get_compliance_details` with the compliance 'id' to get complete information
    """
    # Lightweight fields for listing
    lightweight_fields = "id,name,provider"

    params: dict[str, str] = {"fields": lightweight_fields}

    if provider:
        params["provider"] = ",".join(provider)

    response = _get_hub_endpoint("compliance", params=params)
    response.raise_for_status()
    compliances = parse_json_response(response)

    # Return compliances as a lightweight list
    compliances_list = []
    for compliance in compliances:
        compliance_data = {
            "id": compliance["id"],
            "name": compliance["name"],
            "provider": compliance["provider"],
        }
        compliances_list.append(compliance_data)

    return {"count": len(compliances), "compliances": compliances_list}


@hub_mcp_server.tool()
async def semantic_search_compliances(
    term: NonBlankStr = Field(
        description="Search term. Examples: 'CIS', 'HIPAA', 'PCI', 'GDPR', 'SOC2', 'NIST'.",
    ),
) -> dict:
    """Search for compliance frameworks using free-text search.

    IMPORTANT: This tool returns LIGHTWEIGHT compliance data. Use this for discovering frameworks by topic.
    For complete details including requirements use `prowler_hub_get_compliance_details`.

    Searches across framework names, descriptions, and metadata. Use this when you
    want to find frameworks related to a specific regulation, standard, or topic.

    Returns:
        {
            "count": N,
            "compliances": [
                {
                    "id": "cis_4.0_aws",
                    "name": "CIS Amazon Web Services Foundations Benchmark v4.0",
                    "provider": "aws",
                },
                ...
            ]
        }
    """
    response = _get_hub_endpoint("compliance", "search", params={"term": term})
    response.raise_for_status()
    compliances = parse_json_response(response)

    # Return compliances as a lightweight list
    compliances_list = []
    for compliance in compliances:
        compliance_data = {
            "id": compliance["id"],
            "name": compliance["name"],
            "provider": compliance["provider"],
        }
        compliances_list.append(compliance_data)

    return {"count": len(compliances), "compliances": compliances_list}


@hub_mcp_server.tool()
async def get_compliance_details(
    compliance_id: NonBlankStr = Field(
        description="The compliance framework ID to retrieve details for. Example: 'cis_4.0_aws'. Use `prowler_hub_list_compliances` or `prowler_hub_semantic_search_compliances` to find available compliance IDs.",
    ),
) -> dict:
    """Retrieve comprehensive details about a specific compliance framework by its ID.

    IMPORTANT: This tool returns COMPLETE compliance details.
    Use this after finding a specific compliance via `prowler_hub_list_compliances` or `prowler_hub_semantic_search_compliances`.

    Returns:
        {
            "id": "string",
            "name": "string",
            "framework": "string",
            "provider": "string",
            "version": "string",
            "description": "string",
            "total_checks": int,
            "total_requirements": int,
            "requirements": [
                {
                    "id": "string",
                    "name": "string",
                    "description": "string",
                    "checks": ["check_id_1", "check_id_2"]
                }
            ]
        }
    """
    try:
        response = _get_hub_endpoint("compliance", compliance_id)
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise ToolError(_COMPLIANCE_NOT_FOUND.format(compliance_id=compliance_id))
        raise

    compliance = parse_json_response(response)

    if not compliance:
        raise ToolError(_COMPLIANCE_NOT_FOUND.format(compliance_id=compliance_id))

    # Build response with only non-empty fields to save tokens
    result = {}

    # Core fields
    result["id"] = compliance["id"]
    if compliance.get("name"):
        result["name"] = compliance["name"]
    if compliance.get("framework"):
        result["framework"] = compliance["framework"]
    if compliance.get("provider"):
        result["provider"] = compliance["provider"]
    if compliance.get("version"):
        result["version"] = compliance["version"]
    if compliance.get("description"):
        result["description"] = compliance["description"]

    # Numeric fields
    if compliance.get("total_checks"):
        result["total_checks"] = compliance["total_checks"]
    if compliance.get("total_requirements"):
        result["total_requirements"] = compliance["total_requirements"]

    # Requirements - filter out empty nested values
    requirements = compliance.get("requirements", [])
    if requirements:
        filtered_requirements = []
        for req in requirements:
            filtered_req = {}
            if req.get("id"):
                filtered_req["id"] = req["id"]
            if req.get("name"):
                filtered_req["name"] = req["name"]
            if req.get("description"):
                filtered_req["description"] = req["description"]
            if req.get("checks"):
                filtered_req["checks"] = req["checks"]
            if filtered_req:
                filtered_requirements.append(filtered_req)
        if filtered_requirements:
            result["requirements"] = filtered_requirements

    return result


# Provider Tools
@hub_mcp_server.tool()
async def list_providers() -> dict:
    """List all providers supported by Prowler.

    This is a reference tool that shows available providers (aws, azure, gcp, kubernetes, etc.)
    that can be scanned for finding security issues.

    Use the provider IDs from this tool as filter values in other tools.

    Returns:
        {
            "count": N,
            "providers": [
                {
                    "id": "aws",
                    "name": "Amazon Web Services"
                },
                {
                    "id": "azure",
                    "name": "Microsoft Azure"
                },
                ...
            ]
        }
    """
    response = _get_hub_endpoint("providers")
    response.raise_for_status()
    providers = parse_json_response(response)

    providers_list = []
    for provider in providers:
        providers_list.append(
            {
                "id": provider["id"],
                "name": provider.get("name", ""),
            }
        )

    return {"count": len(providers), "providers": providers_list}


@hub_mcp_server.tool()
async def get_provider_services(
    provider_id: NonBlankStr = Field(
        description="The provider ID to get services for. Example: 'aws', 'azure', 'gcp', 'kubernetes'. Use `prowler_hub_list_providers` to get available provider IDs.",
    ),
) -> dict:
    """Get the list of services IDs available for a specific cloud provider.

    Services represent the different resources and capabilities that Prowler can scan
    within a provider (e.g., s3, ec2, iam for AWS or keyvault, storage for Azure).

    Use service IDs from this tool as filter values in other tools.

    Returns:
        {
            "provider_id": "aws",
            "provider_name": "Amazon Web Services",
            "count": N,
            "services": ["s3", "ec2", "iam", "rds", "lambda", ...]
        }
    """
    response = _get_hub_endpoint("providers")
    response.raise_for_status()
    providers = parse_json_response(response)

    for provider in providers:
        if provider["id"] == provider_id:
            return {
                "provider_id": provider["id"],
                "provider_name": provider.get("name", ""),
                "count": len(provider.get("services", [])),
                "services": provider.get("services", []),
            }

    known = ", ".join(sorted(str(provider["id"]) for provider in providers))
    raise ToolError(
        f"Prowler has no provider with the ID '{provider_id}'. Available: {known}."
    )
