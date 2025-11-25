"""Resource Inventory tools for Prowler App MCP Server."""

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_resources(
    provider_type: list[str] | None = None,
    provider_alias: str | None = None,
    service: list[str] | None = None,
    region: list[str] | None = None,
    resource_type: list[str] | None = None,
    resource_name: str | None = None,
    resource_uid: str | None = None,
    tag_key: str | None = None,
    tag_value: str | None = None,
    tag: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    include_findings: bool = False,
    include_provider: bool = False,
    page_size: int = 100,
    page_number: int = 1,
) -> dict[str, any]:
    """Search and explore cloud resources discovered by Prowler across all providers.

    By default retrieves the latest resources from the most recent scans. Can filter by provider,
    service, region, resource type, tags, and more.

    Args:
        provider_type: Filter by cloud provider
        provider_alias: Filter by specific provider alias/name
        service: Filter by cloud service (e.g., s3, ec2, iam)
        region: Filter by cloud regions
        resource_type: Filter by resource type (e.g., bucket, instance, user)
        resource_name: Search by resource name (supports partial matching)
        resource_uid: Search by resource unique identifier
        tag_key: Filter by tag key
        tag_value: Filter by tag value
        tag: Filter by tag (key:value format)
        date_from: Start date for historical query (YYYY-MM-DD). Enables historical mode.
        date_to: End date for historical query (YYYY-MM-DD). Enables historical mode.
        search: Free-text search across resource details
        include_findings: Include associated findings for each resource. Default: False
        include_provider: Include full provider details. Default: False
        page_size: Number of results per page. Default: 100, Max: 1000
        page_number: Page number to retrieve (1-indexed). Default: 1

    Returns:
        Paginated list of cloud resources with metadata and failed findings count

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    # Determine endpoint based on date parameters
    date_range = client.normalize_date_range(date_from, date_to, max_days=2)

    if date_range is None:
        endpoint = "/api/v1/resources/latest"
        params = {}
    else:
        endpoint = "/api/v1/resources"
        params = {
            "filter[updated_at__gte]": date_range[0],
            "filter[updated_at__lte]": date_range[1],
        }

    # Build filter parameters
    if provider_type:
        params["filter[provider_type__in]"] = provider_type
    if provider_alias:
        params["filter[provider_alias__icontains]"] = provider_alias
    if service:
        params["filter[service__in]"] = service
    if region:
        params["filter[region__in]"] = region
    if resource_type:
        params["filter[type__in]"] = resource_type
    if resource_name:
        params["filter[name__icontains]"] = resource_name
    if resource_uid:
        params["filter[uid__icontains]"] = resource_uid
    if tag_key:
        params["filter[tags__key]"] = tag_key
    if tag_value:
        params["filter[tags__value]"] = tag_value
    if tag:
        params["filter[tags]"] = tag
    if search:
        params["filter[search]"] = search

    # Include relationships
    includes = []
    if include_findings:
        includes.append("findings")
    if include_provider:
        includes.append("provider")
    if includes:
        params["include"] = ",".join(includes)

    # Pagination
    params["page[size]"] = page_size
    params["page[number]"] = page_number

    clean_params = client.build_filter_params(params)

    return await client.get(endpoint, params=clean_params)


async def get_resource_details(
    resource_id: str,
    include_findings: bool = False,
    include_provider: bool = False,
) -> dict[str, any]:
    """Retrieve comprehensive details about a specific cloud resource by its ID.

    Returns resource metadata including name, type, region, service, tags, associated findings,
    and provider information.

    Args:
        resource_id: UUID of the resource to retrieve
        include_findings: Include all associated findings. Default: False
        include_provider: Include full provider details. Default: False

    Returns:
        Detailed information for a specific resource including optional findings and provider details

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {}
    includes = []
    if include_findings:
        includes.append("findings")
    if include_provider:
        includes.append("provider")
    if includes:
        params["include"] = ",".join(includes)

    return await client.get(f"/api/v1/resources/{resource_id}", params=params)


async def get_resource_metadata(
    provider_type: list[str] | None = None,
    provider_alias: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, any]:
    """Retrieve available metadata values for dynamic filtering of resources.

    Returns unique lists of services, regions, and resource types across the environment.
    By default retrieves metadata from the latest scans.

    Args:
        provider_type: Filter metadata by provider
        provider_alias: Filter by specific provider alias/name
        date_from: Start date for historical metadata query (YYYY-MM-DD). Enables historical mode.
        date_to: End date for historical metadata query (YYYY-MM-DD). Enables historical mode.

    Returns:
        Available metadata values for dynamic filtering (services, regions, resource types)

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    # Determine endpoint based on date parameters
    date_range = client.normalize_date_range(date_from, date_to, max_days=2)

    if date_range is None:
        endpoint = "/api/v1/resources/metadata/latest"
        params = {}
    else:
        endpoint = "/api/v1/resources/metadata"
        params = {
            "filter[updated_at__gte]": date_range[0],
            "filter[updated_at__lte]": date_range[1],
        }

    if provider_type:
        params["filter[provider_type__in]"] = provider_type
    if provider_alias:
        params["filter[provider_alias__icontains]"] = provider_alias

    clean_params = client.build_filter_params(params)

    return await client.get(endpoint, params=clean_params)
