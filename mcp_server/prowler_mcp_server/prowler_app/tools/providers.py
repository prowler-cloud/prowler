"""Cloud Provider Management tools for Prowler App MCP Server."""

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_cloud_providers(
    provider_id: list[str] | None = None,
    provider_type: list[str] | None = None,
    alias: str | None = None,
    connected: bool | None = None,
    include_secret_info: bool = False,
) -> dict[str, any]:
    """View and search configured cloud providers with their connection status.

    Returns a unified view of all cloud accounts across AWS, Azure, GCP, K8s, M365, and GitHub.
    Supports filtering by type, connection status, or alias.

    Args:
        provider_id: Get details for a specific provider ID. Use this parameter alone.
        provider_type: Filter by cloud type
        alias: Search by provider alias/name
        connected: Filter by connection status. True for connected only, False for failed connections
        include_secret_info: Include associated secret metadata (not secret values). Default: False

    Returns:
        List of configured cloud providers with connection status and metadata

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    # If specific provider_id requested, fetch individual provider(s)
    if provider_id:
        if len(provider_id) == 1:
            # Single provider - get details
            provider_uuid = provider_id[0]
            params = {}
            if include_secret_info:
                params["include"] = "secret"
            return await client.get(f"/api/v1/providers/{provider_uuid}", params=params)
        else:
            # Multiple providers - use filter
            params = {
                "filter[id__in]": provider_id,
            }
    else:
        params = {}

    # Build filter parameters
    if provider_type:
        params["filter[provider__in]"] = provider_type
    if alias:
        params["filter[alias__icontains]"] = alias
    if connected is not None:
        params["filter[connected]"] = connected

    clean_params = client.build_filter_params(params)

    return await client.get("/api/v1/providers", params=clean_params)


async def connect_provider(
    provider_uid: str,
    alias: str | None = None,
    credentials: dict[str, any] | None = None,
) -> dict[str, any]:
    """Connect new or existing Prowler provider for scanning.

    Handles the complete workflow: stores credentials securely, configures the provider,
    and verifies the connection works. Returns connection status and any configuration issues.
    Smart defaults based on cloud type (AWS role-based auth, Azure service principal, GCP service account, etc.).

    Args:
        provider_uid: Unique identifier for the provider, set by the provider
                     (AWS account ID, Azure subscription ID, GCP project ID, etc.)
        alias: Friendly name for this provider (e.g., "Production AWS", "Dev Azure")
        credentials: Cloud-specific credentials object. If not provided, the provider will be created without auth.
                    Structure varies by provider:
                    - AWS: {role_arn: string} or {access_key_id: string, secret_access_key: string}
                    - Azure: {tenant_id: string, client_id: string, client_secret: string}
                    - GCP: {service_account_key: object}
                    - K8s: {kubeconfig: string}

    Returns:
        The created/updated provider with connection status information

    Raises:
        Exception: If API request fails or provider cannot be connected
    """
    client = ProwlerAPIClient()

    # Step 1: Check if provider already exists
    logger.info(f"Checking if provider {provider_uid} exists...")
    try:
        existing_providers = await client.get(
            "/api/v1/providers", params={"filter[uid]": provider_uid}
        )
        provider_exists = (
            existing_providers.get("data") and len(existing_providers["data"]) > 0
        )

        if provider_exists:
            provider_data = existing_providers["data"][0]
            provider_id = provider_data["id"]
            logger.info(f"Provider {provider_uid} already exists with ID {provider_id}")
        else:
            provider_id = None
            logger.info(f"Provider {provider_uid} does not exist, will create")
    except Exception as e:
        logger.error(f"Error checking provider existence: {e}")
        provider_exists = False
        provider_id = None

    # Step 2: Create or update provider
    if not provider_exists:
        logger.info(f"Creating provider {provider_uid}...")
        provider_body = {
            "data": {
                "type": "providers",
                "attributes": {
                    "uid": provider_uid,
                },
            }
        }
        if alias:
            provider_body["data"]["attributes"]["alias"] = alias

        provider_response = await client.post(
            "/api/v1/providers", json_data=provider_body
        )
        provider_id = provider_response["data"]["id"]
        logger.info(f"Provider created with ID {provider_id}")
    elif alias:
        # Update alias if provider exists and alias is provided
        logger.info(f"Updating provider {provider_id} alias...")
        update_body = {
            "data": {
                "type": "providers",
                "id": provider_id,
                "attributes": {
                    "alias": alias,
                },
            }
        }
        await client.patch(f"/api/v1/providers/{provider_id}", json_data=update_body)

    # Step 3: Handle credentials if provided
    if credentials:
        logger.info(f"Adding/updating credentials for provider {provider_id}...")

        # Determine secret type from credentials structure
        if "role_arn" in credentials:
            secret_type = "role"
        elif "service_account_key" in credentials:
            secret_type = "service_account"
        else:
            secret_type = "static"

        secret_body = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "secret_type": secret_type,
                    "credentials": credentials,
                },
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "providers",
                            "id": provider_id,
                        }
                    }
                },
            }
        }

        try:
            await client.post("/api/v1/providers/secrets", json_data=secret_body)
            logger.info("Credentials added successfully")
        except Exception as e:
            logger.warning(f"Error adding credentials (might already exist): {e}")
            # Try updating existing secret
            try:
                secrets_response = await client.get(
                    "/api/v1/providers/secrets",
                    params={"filter[provider]": provider_id},
                )
                if secrets_response.get("data"):
                    secret_id = secrets_response["data"][0]["id"]
                    update_secret_body = {
                        "data": {
                            "type": "provider-secrets",
                            "id": secret_id,
                            "attributes": {
                                "secret_type": secret_type,
                                "credentials": credentials,
                            },
                        }
                    }
                    await client.patch(
                        f"/api/v1/providers/secrets/{secret_id}",
                        json_data=update_secret_body,
                    )
                    logger.info("Credentials updated successfully")
            except Exception as update_error:
                logger.error(f"Error updating credentials: {update_error}")
                raise

    # Step 4: Test connection
    logger.info(f"Testing connection for provider {provider_id}...")
    try:
        connection_response = await client.post(
            f"/api/v1/providers/{provider_id}/connection", json_data={}
        )
        connection_status = connection_response.get("data", {}).get("attributes", {})
        logger.info(f"Connection test result: {connection_status}")
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        connection_status = {"connected": False, "error": str(e)}

    # Step 5: Get final provider state
    final_provider = await client.get(f"/api/v1/providers/{provider_id}")

    return {
        "data": final_provider.get("data"),
        "status": "connected" if connection_status.get("connected") else "failed",
        "message": (
            "Provider connected successfully and credentials verified"
            if connection_status.get("connected")
            else f"Provider configured but connection failed: {connection_status.get('error', 'Unknown error')}"
        ),
    }


async def delete_provider(
    provider_id: str,
) -> dict[str, any]:
    """Remove a Prowler provider.

    Stops future scans and cleans up unused credentials.

    Args:
        provider_id: UUID of the provider to remove

    Returns:
        Confirmation of deletion

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    logger.info(f"Deleting provider {provider_id}...")
    await client.delete(f"/api/v1/providers/{provider_id}")

    return {
        "status": "deleted",
        "message": f"Provider {provider_id} deleted successfully",
    }
