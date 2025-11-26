"""Cloud Provider Management tools for Prowler App MCP Server.

This module provides tools for managing cloud provider connections,
including searching, connecting, and deleting providers.
"""

from typing import Any

from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class ProvidersTools(BaseTool):
    """Tools for cloud provider management operations.

    Provides tools for:
    - Searching and viewing configured providers
    - Connecting new providers with credentials
    - Deleting providers
    """

    async def search_cloud_providers(
        self,
        provider_id: list[str] | None = Field(
            default=None,
            description="Get details for specific provider UUID(s). Multiple values allowed. When provided, other filters are ignored",
        ),
        provider_type: list[str] | None = Field(
            default=None,
            description="Filter by cloud type. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
        ),
        alias: str | None = Field(
            default=None,
            description="Search by provider alias/name (partial match supported)",
        ),
        connected: bool | None = Field(
            default=None,
            description="Filter by connection status. True for connected only, False for failed connections",
        ),
        include_secret_info: bool = Field(
            default=False,
            description="Include associated secret metadata (not secret values) in response",
        ),
    ) -> dict[str, Any]:
        """View and search configured cloud providers with their connection status.

        Returns a unified view of all cloud accounts across AWS, Azure, GCP, K8s, M365, and GitHub.
        Supports filtering by type, connection status, or alias.

        Returns:
            dict containing the API response with list of configured cloud providers,
            their connection status, and metadata
        """
        # If specific provider_id requested, fetch individual provider(s)
        if provider_id:
            if len(provider_id) == 1:
                # Single provider - get details
                provider_uuid = provider_id[0]
                params = {}
                if include_secret_info:
                    params["include"] = "secret"
                return await self.api_client.get(
                    f"/api/v1/providers/{provider_uuid}", params=params
                )
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

        clean_params = self.api_client.build_filter_params(params)

        return await self.api_client.get("/api/v1/providers", params=clean_params)

    async def connect_provider(
        self,
        provider_uid: str = Field(
            description="Unique identifier for the provider (AWS account ID, Azure subscription ID, GCP project ID, etc.)"
        ),
        alias: str | None = Field(
            default=None,
            description="Friendly name for this provider (e.g., 'Production AWS', 'Dev Azure')",
        ),
        credentials: dict[str, Any] | None = Field(
            default=None,
            description="Cloud-specific credentials object. Structure varies by provider: AWS (role_arn or access_key_id/secret_access_key), Azure (tenant_id/client_id/client_secret), GCP (service_account_key), K8s (kubeconfig). If not provided, provider is created without credentials",
        ),
    ) -> dict[str, Any]:
        """Connect new or existing Prowler provider for scanning.

        Handles the complete workflow: stores credentials securely, configures the provider,
        and verifies the connection works. Returns connection status and any configuration issues.
        Smart defaults based on cloud type (AWS role-based auth, Azure service principal,
        GCP service account, etc.).

        Returns:
            dict containing the provider data, connection status, and status message
        """
        # Step 1: Check if provider already exists
        self.logger.info(f"Checking if provider {provider_uid} exists...")
        try:
            existing_providers = await self.api_client.get(
                "/api/v1/providers", params={"filter[uid]": provider_uid}
            )
            provider_exists = (
                existing_providers.get("data") and len(existing_providers["data"]) > 0
            )

            if provider_exists:
                provider_data = existing_providers["data"][0]
                provider_id = provider_data["id"]
                self.logger.info(
                    f"Provider {provider_uid} already exists with ID {provider_id}"
                )
            else:
                provider_id = None
                self.logger.info(f"Provider {provider_uid} does not exist, will create")
        except Exception as e:
            self.logger.error(f"Error checking provider existence: {e}")
            provider_exists = False
            provider_id = None

        # Step 2: Create or update provider
        if not provider_exists:
            self.logger.info(f"Creating provider {provider_uid}...")
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

            provider_response = await self.api_client.post(
                "/api/v1/providers", json_data=provider_body
            )
            provider_id = provider_response["data"]["id"]
            self.logger.info(f"Provider created with ID {provider_id}")
        elif alias:
            # Update alias if provider exists and alias is provided
            self.logger.info(f"Updating provider {provider_id} alias...")
            update_body = {
                "data": {
                    "type": "providers",
                    "id": provider_id,
                    "attributes": {
                        "alias": alias,
                    },
                }
            }
            await self.api_client.patch(
                f"/api/v1/providers/{provider_id}", json_data=update_body
            )

        # Step 3: Handle credentials if provided
        if credentials:
            self.logger.info(
                f"Adding/updating credentials for provider {provider_id}..."
            )

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
                await self.api_client.post(
                    "/api/v1/providers/secrets", json_data=secret_body
                )
                self.logger.info("Credentials added successfully")
            except Exception as e:
                self.logger.warning(
                    f"Error adding credentials (might already exist): {e}"
                )
                # Try updating existing secret
                try:
                    secrets_response = await self.api_client.get(
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
                        await self.api_client.patch(
                            f"/api/v1/providers/secrets/{secret_id}",
                            json_data=update_secret_body,
                        )
                        self.logger.info("Credentials updated successfully")
                except Exception as update_error:
                    self.logger.error(f"Error updating credentials: {update_error}")
                    raise

        # Step 4: Test connection
        self.logger.info(f"Testing connection for provider {provider_id}...")
        try:
            connection_response = await self.api_client.post(
                f"/api/v1/providers/{provider_id}/connection", json_data={}
            )
            connection_status = connection_response.get("data", {}).get(
                "attributes", {}
            )
            self.logger.info(f"Connection test result: {connection_status}")
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            connection_status = {"connected": False, "error": str(e)}

        # Step 5: Get final provider state
        final_provider = await self.api_client.get(f"/api/v1/providers/{provider_id}")

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
        self,
        provider_id: str = Field(description="UUID of the provider to remove"),
    ) -> dict[str, Any]:
        """Remove a Prowler provider.

        Stops future scans and cleans up unused credentials.

        Returns:
            dict containing status and confirmation message
        """
        self.logger.info(f"Deleting provider {provider_id}...")
        await self.api_client.delete(f"/api/v1/providers/{provider_id}")

        return {
            "status": "deleted",
            "message": f"Provider {provider_id} deleted successfully",
        }
