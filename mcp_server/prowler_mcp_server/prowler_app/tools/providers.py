"""Cloud Provider Management tools for Prowler App MCP Server.

This module provides tools for managing cloud provider connections,
including searching, connecting, and deleting providers.
"""

from typing import Any

from prowler_mcp_server.prowler_app.models.providers import (
    ProviderConnectionStatus,
    ProvidersListResponse,
)
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
        provider_id: list[str] = Field(
            default=[],
            description="Filter by Prowler's internal UUID(s) (v4) for the provider(s), generated when the provider is registered in the system.",
        ),
        provider_uid: list[str] = Field(
            default=[],
            description="Filter by provider's unique identifier(s). Format varies by provider type: AWS Account ID (12 digits), Azure Subscription ID (UUID), GCP Project ID (string), Kubernetes namespace, GitHub username/organization, M365 domain ID, etc. All supported provider types are listed in the Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by cloud provider type. Valid values include: 'aws', 'azure', 'gcp', 'kubernetes'... For more valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server.",
        ),
        alias: str | None = Field(
            default=None,
            description="Search by provider alias/friendly name. Partial match supported (case-insensitive). Use this to find providers by their human-readable name (e.g., 'Production', 'Dev', 'AWS Main')",
        ),
        connected: (
            bool | str | None
        ) = Field(  # Wrong `str` hint type due to bad MCP Clients implementation
            default=None,
            description="Filter by connection status. True returns only successfully connected providers (credentials work), False returns only providers with failed connections (credentials invalid). If not specified, returns all connected, failed and not tested providers. Strings 'true' and 'false' are also accepted.",
        ),
        page_size: int = Field(
            default=50, description="Number of results to return per page"
        ),
        page_number: int = Field(
            default=1,
            description="Page number to retrieve (1-indexed)",
        ),
    ) -> dict[str, Any]:
        """Search and view configured cloud providers with their connection status.

        This tool returns a unified view of all cloud accounts/subscriptions/projects configured in Prowler.
        Each provider represents a cloud account (AWS account ID, Azure subscription, GCP project, K8s cluster, etc.)
        that has been added for security scanning.

        For getting more details about what types of providers are available or what are the IDs format for each provider type, please refer to Prowler Hub/Prowler Documentation
        that you can also find in form of tools in this MCP Server.

        Each provider includes:
        - Provider identification: id, uid, alias
        - Cloud context: provider type
        - Connection status: connected

        Returns:
            dict with 'providers' array, pagination info (total_num_providers, total_num_pages, current_page)
        """
        self.api_client.validate_page_size(page_size)

        params = {
            "fields[providers]": "uid,alias,provider,connection",
            "page[number]": page_number,
            "page[size]": page_size,
        }

        # Build filter parameters
        if provider_id:
            params["filter[id__in]"] = provider_id
        if provider_uid:
            params["filter[uid__in]"] = provider_uid
        if provider_type:
            params["filter[provider__in]"] = provider_type
        if alias:
            params["filter[alias__icontains]"] = alias
        if connected is not None:
            params["filter[connected]"] = (
                connected
                if isinstance(connected, bool)
                else connected.lower() == "true"
            )

        clean_params = self.api_client.build_filter_params(params)

        api_response = await self.api_client.get(
            "/api/v1/providers", params=clean_params
        )
        simplified_response = ProvidersListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def connect_provider(
        self,
        provider_uid: str = Field(
            description="Provider's unique identifier. For supported UID provider formats, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server"
        ),
        provider_type: str = Field(
            description="Type of cloud provider. Valid values include: 'aws', 'azure', 'gcp', 'kubernetes'... For more valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server."
        ),
        alias: str | None = Field(
            default=None,
            description="Human-friendly name for this provider. Optional but recommended for easy identification. Use descriptive names to distinguish multiple accounts of the same type.",
        ),
        credentials: dict[str, Any] | None = Field(
            default=None,
            description="Cloud-specific credentials for authentication. Optional - if not provided, provider is created but not connected. Structure varies by provider type. For supported provider types, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server",
        ),
    ) -> dict[str, Any]:
        """Connect or register a cloud provider account for security scanning in Prowler.

        This tool performs a complete provider onboarding workflow:
        1. Checks if provider already exists
        2. Creates new provider if it doesn't exist or updates existing one
        3. Stores credentials securely
        4. Tests connection to verify credentials work
        5. Returns provider details with connection status

        The tool is idempotent - calling it multiple times with the same provider_uid will:
        - Update the alias if provided
        - Update credentials if provided
        - Re-test the connection

        Example Input:
        AWS Static Credentials:
        ```json
        {
            "provider_uid": "123456789012",
            "provider_type": "aws",
            "alias": "production-aws-account",
            "credentials": {
                "aws_access_key_id": "AKIA...",
                "aws_secret_access_key": "...",
                "aws_session_token": "..."
            }
        }
        ```
        AWS Assume Role:
        ```json
        {
            "provider_uid": "987654321098",
            "provider_type": "aws",
            "alias": "staging-aws-account",
            "credentials": {
                "role_arn": "arn:aws:iam::987654321098:role/ProwlerScanRole",
                "external_id": "...",
                "aws_access_key_id": "AKIA...",   # Optional
                "aws_secret_access_key": "...",   # Optional
                "aws_session_token": "...",   # Optional
                "session_duration": 3600,   # Optional
                "role_session_name": "..."   # Optional
            }
        }
        ```
        Azure/M365 Static Credentials:
        ```json
        {
            "provider_uid": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
            "provider_type": "azure",
            "alias": "production-azure-subscription",
            "credentials": {
                "client_id": "...",
                "client_secret": "...",
                "tenant_id": "..."
            }
        }
        ```
        GCP Service Account Account Key:
        ```json
        {
            "provider_uid": "my-gcp-project-prod",
            "provider_type": "gcp",
            "alias": "production-gcp-project",
            "credentials": {
                "service_account_key": {
                    "type": "service_account",
                    "project_id": "...",
                    "private_key_id": "...",
                    "private_key": "...",
                    "client_email": "...",
                }
            }
        }
        ```
        Kubernetes Static Credentials:
        ```json
        {
            "provider_uid": "prod-k8s-cluster",
            "provider_type": "kubernetes",
            "alias": "production-kubernetes-cluster",
            "credentials": {
                "kubeconfig_content": "..."
            }
        }
        ```
        GitHub OAuth App Token:
        ```json
        {
            "provider_uid": "my-organization",
            "provider_type": "github",
            "alias": "my-github-organization",
            "credentials": {
                "oauth_app_token": "..."
            }
        }

        NOTE: THERE ARE MORE PROVIDER TYPES AND CREDENTIAL TYPES AVAILABLE, PLEASE REFER TO THE Prowler Documentation that you can also find in form of tools in this MCP Server.

        Response structure:
        - provider: Detailed provider object with all metadata
        - status: "connected" if credentials work, "failed" if connection test failed
        - message: Human-readable status message with error details if failed

        Returns:
            dict with provider details, connection status ("connected" or "failed"), and status message
        """
        # Step 1: Check if provider already exists
        prowler_provider_id = await self._check_provider_exists(provider_uid)

        # Step 2: Create or update provider
        if prowler_provider_id is None:
            prowler_provider_id = await self._create_provider(
                provider_uid, provider_type, alias
            )
        elif alias:
            await self._update_provider_alias(prowler_provider_id, alias)

        # Step 3: Handle credentials if provided
        if credentials:
            await self._store_credentials(prowler_provider_id, credentials)

        # Step 4: Test connection
        connection_status = await self._test_connection(prowler_provider_id)

        # Step 5: Get final provider state with relationships
        final_provider = await self._get_final_provider_state(prowler_provider_id)

        # Transform to structured response using model
        connection_result = ProviderConnectionStatus.create(
            provider_data=final_provider["data"],
            connection_status=connection_status,
        )

        return connection_result.model_dump()

    async def delete_provider(
        self,
        provider_id: str = Field(
            description="Prowler's internal UUID (v4) for the provider to permanently remove, generated when the provider was registered in the system. Use `prowler_app_search_cloud_providers` tool to find the provider_id if you only know the alias or the provider's own identifier (provider_uid)"
        ),
    ) -> dict[str, Any]:
        """Permanently remove a cloud provider from Prowler.

        WARNING: This is a destructive operation that cannot be undone. The provider will need to be
        re-added with connect_provider if you want to scan it again.

        Response structure:
        - status: "deleted" on success
        - message: Confirmation message with the deleted provider_id

        Returns:
            dict with deletion confirmation status and message
        """
        self.logger.info(f"Deleting provider {provider_id}...")
        try:
            # Initiate the deletion task
            task_response = await self.api_client.delete(
                f"/api/v1/providers/{provider_id}"
            )
            task_id = task_response.get("data", {}).get("id")

            # Poll until task completes (with 60 second timeout)
            await self.api_client.poll_task_until_complete(
                task_id=task_id, timeout=60, poll_interval=1.0
            )

            # If we reach here, the task completed successfully
            return {
                "deleted": True,
                "message": f"Provider {provider_id} deleted successfully",
            }
        except Exception as e:
            self.logger.error(f"Provider deletion failed: {e}")
            return {
                "deleted": False,
                "message": f"Provider {provider_id} deletion failed: {str(e)}",
            }

    # Private helper methods

    async def _check_provider_exists(self, provider_uid: str) -> str | None:
        """Check if a provider already exists by its UID.

        Args:
            provider_uid: The cloud provider's unique identifier (e.g., AWS account ID)

        Returns:
            The Prowler-generated provider ID if exists, None otherwise

        Raises:
            Exception: If multiple providers with the same UID are found (data integrity issue)
            Exception: If API request fails
        """
        self.logger.info(f"Checking if provider {provider_uid} exists...")
        response = await self.api_client.get(
            "/api/v1/providers", params={"filter[uid]": provider_uid}
        )
        providers = response.get("data", [])

        if len(providers) == 0:
            self.logger.info(f"Provider {provider_uid} does not exist")
            return None
        elif len(providers) == 1:
            prowler_provider_id = providers[0].get("id")
            self.logger.info(
                f"Provider {provider_uid} exists with ID {prowler_provider_id}"
            )
            return prowler_provider_id
        else:
            # Multiple providers with the same UID is a data integrity issue
            raise Exception(
                f"Data integrity error: Found {len(providers)} providers with UID '{provider_uid}'. "
                f"Each provider UID should be unique. Please contact support or manually clean up duplicate providers."
            )

    async def _create_provider(
        self, provider_uid: str, provider_type: str, alias: str | None
    ) -> str:
        """Create a new provider.

        Args:
            provider_uid: The cloud provider's unique identifier
            provider_type: Type of cloud provider (aws, azure, gcp, etc.)
            alias: Optional human-friendly name for the provider

        Returns:
            The provider UID (which is used as the ID)
        """
        self.logger.info(f"Creating provider {provider_uid} (type: {provider_type})...")
        provider_body = {
            "data": {
                "type": "providers",
                "attributes": {
                    "uid": provider_uid,
                    "provider": provider_type,
                },
            }
        }
        if alias:
            provider_body["data"]["attributes"]["alias"] = alias

        await self.api_client.post("/api/v1/providers", json_data=provider_body)

        provider_id = await self._check_provider_exists(provider_uid)
        if provider_id is None:
            raise Exception(f"Provider {provider_uid} creation failed")
        return provider_id

    async def _update_provider_alias(
        self, prowler_provider_id: str, alias: str
    ) -> None:
        """Update the alias of an existing provider.

        Args:
            prowler_provider_id: The Prowler-generated provider ID
            alias: New human-friendly name for the provider
        """
        self.logger.info(f"Updating provider {prowler_provider_id} alias...")
        update_body = {
            "data": {
                "type": "providers",
                "id": prowler_provider_id,
                "attributes": {
                    "alias": alias,
                },
            }
        }
        result = await self.api_client.patch(
            f"/api/v1/providers/{prowler_provider_id}", json_data=update_body
        )
        if result.get("data", {}).get("attributes", {}).get("alias") != alias:
            raise Exception(f"Provider {prowler_provider_id} alias update failed")

    def _determine_secret_type(self, credentials: dict[str, Any]) -> str:
        """Determine the secret type from credentials structure.

        Args:
            credentials: The credentials dictionary

        Returns:
            Secret type: "role", "service_account", or "static"
        """
        if "role_arn" in credentials:
            return "role"
        elif "service_account_key" in credentials:
            return "service_account"
        else:
            return "static"

    async def _get_provider_secret_id(self, prowler_provider_id: str) -> str | None:
        """Get the secret ID for a provider if it exists.

        Args:
            prowler_provider_id: The Prowler-generated provider ID

        Returns:
            The secret ID if exists, None otherwise
        """
        try:
            response = await self.api_client.get(
                "/api/v1/providers/secrets",
                params={"filter[provider]": prowler_provider_id},
            )
            secrets = response.get("data", [])

            if len(secrets) > 0:
                secret_id = secrets[0].get("id")
                self.logger.info(
                    f"Found existing secret {secret_id} for provider {prowler_provider_id}"
                )
                return secret_id
            else:
                self.logger.info(
                    f"No existing secret found for provider {prowler_provider_id}"
                )
                return None
        except Exception as e:
            self.logger.error(f"Error checking for existing secret: {e}")
            return None

    async def _store_credentials(
        self, prowler_provider_id: str, credentials: dict[str, Any]
    ) -> None:
        """Store or update credentials for a provider.

        Args:
            prowler_provider_id: The Prowler-generated provider ID
            credentials: The credentials to store
        """
        self.logger.info(
            f"Adding/updating credentials for provider {prowler_provider_id}..."
        )

        secret_type = self._determine_secret_type(credentials)

        # Check if a secret already exists for this provider
        existing_secret_id = await self._get_provider_secret_id(prowler_provider_id)

        if existing_secret_id:
            # Update existing secret
            self.logger.info(f"Updating existing secret {existing_secret_id}...")
            update_body = {
                "data": {
                    "type": "provider-secrets",
                    "id": existing_secret_id,
                    "attributes": {
                        "secret_type": secret_type,
                        "secret": credentials,
                    },
                    "relationships": {
                        "provider": {
                            "data": {
                                "type": "providers",
                                "id": prowler_provider_id,
                            }
                        }
                    },
                }
            }
            try:
                await self.api_client.patch(
                    f"/api/v1/providers/secrets/{existing_secret_id}",
                    json_data=update_body,
                )
                self.logger.info("Credentials updated successfully")
            except Exception as e:
                self.logger.error(f"Error updating credentials: {e}")
        else:
            # Create new secret
            self.logger.info("Creating new secret...")
            secret_body = {
                "data": {
                    "type": "provider-secrets",
                    "attributes": {
                        "secret_type": secret_type,
                        "secret": credentials,
                    },
                    "relationships": {
                        "provider": {
                            "data": {
                                "type": "providers",
                                "id": prowler_provider_id,
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
                self.logger.error(f"Error adding credentials: {e}")

    async def _test_connection(self, prowler_provider_id: str) -> dict[str, Any]:
        """Test connection to a provider.

        Args:
            prowler_provider_id: The Prowler-generated provider ID

        Returns:
            Connection status dictionary with 'connected' boolean and optional 'error' message
        """
        self.logger.info(f"Testing connection for provider {prowler_provider_id}...")
        try:
            # Initiate the connection test task
            task_response = await self.api_client.post(
                f"/api/v1/providers/{prowler_provider_id}/connection", json_data={}
            )
            task_id = task_response.get("data", {}).get("id")

            # Poll until task completes (with 60 second timeout)
            completed_task = await self.api_client.poll_task_until_complete(
                task_id=task_id, timeout=60, poll_interval=1.0
            )

            # Extract the result from the completed task
            task_result = (
                completed_task.get("data", {}).get("attributes", {}).get("result", {})
            )

            return task_result
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return {"connected": False, "error": str(e)}

    async def _get_final_provider_state(
        self, prowler_provider_id: str
    ) -> dict[str, Any]:
        """Get final provider state with relationships.

        Args:
            prowler_provider_id: The Prowler-generated provider ID

        Returns:
            Provider data dictionary
        """
        return await self.api_client.get(
            f"/api/v1/providers/{prowler_provider_id}",
        )
