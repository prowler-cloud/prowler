"""Integrations tools for Prowler MCP Server.

This module provides tools for managing where Prowler sends its results, including:
- Generic integration lifecycle (list, get, update, delete, connection check)
- Integration creation, with one tool per integration type
- Jira specific operations (available issue types, sending findings as work items)
"""

import json
from typing import Any

from pydantic import Field

from prowler_mcp_server.prowler_app.models.integrations import (
    DetailedIntegration,
    IntegrationConnectionStatus,
    IntegrationsListResponse,
    JiraDispatchResult,
    JiraIssueTypes,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIError

# The configuration is deliberately left out of the list view, it belongs to the
# detailed view returned by prowler_get_integration
INTEGRATION_LIST_FIELDS = (
    "enabled,connected,connection_last_checked_at,integration_type,providers,"
    "inserted_at,updated_at"
)

CONNECTION_CHECK_TIMEOUT = 120
# One Jira work item is created per finding, sequentially, so this needs to be generous
JIRA_DISPATCH_TIMEOUT = 300

# The API replaces the whole credentials object, so a partial one destroys the rest
JIRA_REQUIRED_CREDENTIALS = ("domain", "user_mail", "api_token")


def _providers_relationship(provider_ids: list[str]) -> dict[str, Any]:
    """Build the JSON:API relationship linkage attaching an integration to providers."""
    return {
        "providers": {
            "data": [
                {"type": "providers", "id": provider_id} for provider_id in provider_ids
            ]
        }
    }


class IntegrationsTools(BaseTool):
    """Tools for integration management operations.

    Provides tools for:
    - prowler_list_integrations: List the configured integrations and their connection state
    - prowler_get_integration: Get an integration with its full configuration
    - prowler_create_amazon_s3_integration: Export scan outputs to an S3 bucket
    - prowler_create_aws_security_hub_integration: Send findings to AWS Security Hub
    - prowler_create_jira_integration: Connect a Jira site to open work items from findings
    - prowler_update_integration: Change credentials, configuration, providers or enabled state
    - prowler_delete_integration: Permanently remove an integration
    - prowler_test_integration_connection: Check an integration connection and refresh its discovered configuration
    - prowler_get_jira_issue_types: List the issue types available in a Jira project
    - prowler_send_findings_to_jira: Create Jira work items for a set of findings
    """

    async def list_integrations(
        self,
        integration_type: list[str] = Field(
            default=[],
            description="Filter by integration type(s). Valid values: 'amazon_s3' (export scan outputs to an S3 bucket), 'aws_security_hub' (send findings to AWS Security Hub), 'jira' (open Jira work items from findings). Leave empty to return every type.",
        ),
        page_size: int = Field(
            default=50, description="Number of results to return per page."
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List the integrations configured in Prowler, with their connection state.

        Integrations are the destinations Prowler sends its results to. They are configured
        per tenant and require the 'manage_integrations' permission.

        IMPORTANT: This tool returns LIGHTWEIGHT integrations without the integration-type
        specific configuration. Use prowler_get_integration to get the full configuration,
        such as the S3 bucket name or the available Jira projects.

        Default behavior:
        - Returns every integration type
        - Returns 50 integrations per page. Tenants normally have a handful of them, so the
          first page usually contains all of them

        Each integration includes:
        - Core identification: id (UUID for prowler_get_integration), integration_type
        - State: enabled, connected (true, false, or null when never checked), connection_last_checked_at
        - Scope: provider_ids, the providers the integration is attached to. Empty means it
          applies to the whole tenant, which is always the case for Jira
        - Temporal data: inserted_at, updated_at timestamps

        NOTE: The API does not support filtering by 'enabled' or 'connected'. Read those
        fields from the returned results instead.

        Workflow:
        1. Use this tool to see which integrations exist and whether they are working
        2. Use prowler_get_integration with the 'id' to get the full configuration
        3. Use prowler_test_integration_connection to re-check a broken integration
        4. Use prowler_update_integration to fix credentials or settings
        """
        self.logger.info("Listing integrations...")
        self.api_client.validate_page_size(page_size)

        params = {
            "fields[integrations]": INTEGRATION_LIST_FIELDS,
            "page[size]": page_size,
            "page[number]": page_number,
        }

        if integration_type:
            params["filter[integration_type__in]"] = integration_type

        clean_params = self.api_client.build_filter_params(params)
        api_response = await self.api_client.get("/integrations", params=clean_params)

        simplified_response = IntegrationsListResponse.from_api_response(api_response)
        return simplified_response.model_dump()

    async def get_integration(
        self,
        integration_id: str = Field(
            description="UUID of the integration to retrieve. Must be a valid UUID format (e.g., '019ac0d6-90d5-73e9-9acf-c22e256f1bac'). Use prowler_list_integrations to find it."
        ),
    ) -> dict[str, Any]:
        """Retrieve an integration with its complete, integration-type specific configuration.

        IMPORTANT: Credentials are never returned by Prowler, only the configuration.

        This tool provides ALL information that prowler_list_integrations returns PLUS the
        'configuration' object, whose contents depend on the integration type:
        - amazon_s3: 'bucket_name' and 'output_directory'
        - aws_security_hub: 'send_only_fails', 'archive_previous_findings' and
          'enabled_regions' (the AWS regions Security Hub is enabled in, discovered by the
          connection check)
        - jira: 'domain', 'projects' (a mapping of project key to project name) and
          'issue_types' (a mapping of project key to its available issue types). Both are
          discovered by the connection check, so an empty 'projects' means the connection
          has not been checked yet

        Workflow:
        1. Use prowler_list_integrations to find the integration 'id'
        2. Use this tool to read its configuration
        3. For Jira, read 'projects' here before calling prowler_get_jira_issue_types
        """
        self.logger.info(f"Retrieving integration {integration_id}...")

        integration = await self._get_integration_raw(integration_id)
        return DetailedIntegration.from_api_response(integration).model_dump()

    async def create_amazon_s3_integration(
        self,
        bucket_name: str = Field(
            description="Name of the S3 bucket where Prowler will upload the scan outputs (CSV, HTML, OCSF JSON and compliance reports)."
        ),
        output_directory: str = Field(
            default="output",
            description='Directory inside the bucket where the outputs are written. Normalized server-side: leading slashes are stripped, the characters < > : " | ? * are rejected and the maximum length is 900 characters.',
        ),
        provider_ids: list[str] = Field(
            default=[],
            description="Prowler UUIDs of the providers whose scan outputs are exported to this bucket. Use prowler_search_providers to find them. Leave empty to attach no provider yet.",
        ),
        role_arn: str | None = Field(
            default=None,
            description="ARN of the IAM role Prowler assumes to write to the bucket (e.g. 'arn:aws:iam::123456789012:role/ProwlerS3Integration'). Recommended over static keys.",
        ),
        external_id: str | None = Field(
            default=None,
            description="External ID required by the trust policy of the assumed role. In Prowler Cloud this is the tenant ID.",
        ),
        role_session_name: str | None = Field(
            default=None,
            description="Identifier for the role session, useful to track it in AWS logs. Only letters, digits and the characters =,.@_- are allowed.",
        ),
        session_duration: int = Field(
            default=3600,
            description="Duration of the assumed role session in seconds. Must be between 900 and 43200. Defaults to 3600 when omitted.",
        ),
        aws_access_key_id: str | None = Field(
            default=None,
            description="AWS access key ID. Only needed when the Prowler deployment has no ambient AWS credentials.",
        ),
        aws_secret_access_key: str | None = Field(
            default=None,
            description="AWS secret access key. Required when 'aws_access_key_id' is provided.",
        ),
        aws_session_token: str | None = Field(
            default=None,
            description="AWS session token, only for temporary credentials.",
        ),
        enabled: bool = Field(
            default=True,
            description="Whether the integration starts enabled. A disabled integration is never used after a scan.",
        ),
    ) -> dict[str, Any]:
        """Create an Amazon S3 integration to export scan outputs to an S3 bucket.

        After every scan of an attached provider, Prowler uploads the generated reports to
        's3://{bucket_name}/{output_directory}/'.

        IMPORTANT: The connection is checked right after creation, and the result is part of
        the response. The check writes and deletes a small test object in the bucket, so the
        credentials need s3:PutObject, s3:ListBucket and s3:DeleteObject on it.

        Default behavior:
        - The integration is created enabled
        - All credential parameters are optional: providing none sends empty credentials,
          which makes Prowler use the ambient AWS credentials of the deployment. That only
          works on self-hosted Prowler, Prowler Cloud requires a role or static keys

        Example Input:
        - IAM role (recommended):
        ```json
        {
            "bucket_name": "my-security-reports",
            "output_directory": "prowler",
            "provider_ids": ["019ac0d6-90d5-73e9-9acf-c22e256f1bac"],
            "role_arn": "arn:aws:iam::123456789012:role/ProwlerS3Integration",
            "external_id": "019ac0d6-90d5-73e9-9acf-c22e256f1bac"
        }
        ```
        - Static credentials:
        ```json
        {
            "bucket_name": "my-security-reports",
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "..."
        }
        ```

        Workflow:
        1. Use prowler_search_providers to get the provider UUIDs to attach
        2. Use this tool to create the integration
        3. Read 'connected' in the response. If it is 'failed', read 'error', then fix the
           bucket policy or the credentials with prowler_update_integration
        """
        self.logger.info(f"Creating Amazon S3 integration for bucket {bucket_name}...")

        try:
            credentials = self._build_aws_credentials(
                role_arn=role_arn,
                external_id=external_id,
                role_session_name=role_session_name,
                session_duration=session_duration,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )

            return await self._create_integration(
                integration_type="amazon_s3",
                configuration={
                    "bucket_name": bucket_name,
                    "output_directory": output_directory,
                },
                credentials=credentials,
                provider_ids=provider_ids,
                enabled=enabled,
            )
        except Exception as e:
            self.logger.error(f"Amazon S3 integration creation failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def create_aws_security_hub_integration(
        self,
        provider_id: str = Field(
            description="Prowler UUID of the AWS provider whose findings are sent to Security Hub. It must be an AWS provider, and it can only have one Security Hub integration. Use prowler_search_providers with provider_type=['aws'] to find it."
        ),
        send_only_fails: bool = Field(
            default=False,
            description="When true, only findings with FAIL status are sent to Security Hub. When false, passed findings are sent too.",
        ),
        archive_previous_findings: bool = Field(
            default=False,
            description="When true, findings that are no longer present in the latest scan are archived in Security Hub.",
        ),
        role_arn: str | None = Field(
            default=None,
            description="ARN of a dedicated IAM role Prowler assumes to write to Security Hub. Leave every credential parameter empty to reuse the credentials already stored for the provider, which is the recommended setup.",
        ),
        external_id: str | None = Field(
            default=None,
            description="External ID required by the trust policy of the assumed role.",
        ),
        role_session_name: str | None = Field(
            default=None,
            description="Identifier for the role session, useful to track it in AWS logs. Only letters, digits and the characters =,.@_- are allowed.",
        ),
        session_duration: int | None = Field(
            default=None,
            description="Duration of the assumed role session in seconds. Must be between 900 and 43200. Defaults to 3600 when omitted.",
        ),
        aws_access_key_id: str | None = Field(
            default=None, description="AWS access key ID for dedicated credentials."
        ),
        aws_secret_access_key: str | None = Field(
            default=None,
            description="AWS secret access key. Required when 'aws_access_key_id' is provided.",
        ),
        aws_session_token: str | None = Field(
            default=None,
            description="AWS session token, only for temporary credentials.",
        ),
        enabled: bool = Field(
            default=True,
            description="Whether the integration starts enabled. A disabled integration is never used after a scan.",
        ),
    ) -> dict[str, Any]:
        """Create an AWS Security Hub integration to send findings to Security Hub in ASFF format.

        After every scan of the attached provider, Prowler pushes its findings to Security Hub
        in every region where the Prowler partner integration is enabled.

        IMPORTANT: The Prowler integration must be enabled in AWS Security Hub beforehand, in
        each region where findings should land. The connection check performed right after
        creation is what discovers those regions and fills 'enabled_regions'.

        Default behavior:
        - The integration is created enabled
        - Leaving every credential parameter empty makes Prowler reuse the credentials already
          stored for the provider. This is the recommended setup
        - send_only_fails defaults to false, so passed findings are sent too

        Constraints:
        - Exactly one provider, and it must be an AWS provider
        - A provider can only have one Security Hub integration. Creating a second one fails
          with a conflict error

        Workflow:
        1. Use prowler_search_providers with provider_type=['aws'] to get the provider UUID
        2. Use this tool to create the integration
        3. Read 'enabled_regions' in the response configuration. If it is empty, the Prowler
           integration is not enabled in Security Hub yet
        """
        self.logger.info(
            f"Creating AWS Security Hub integration for provider {provider_id}..."
        )

        try:
            credentials = self._build_aws_credentials(
                role_arn=role_arn,
                external_id=external_id,
                role_session_name=role_session_name,
                session_duration=session_duration,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )

            return await self._create_integration(
                integration_type="aws_security_hub",
                configuration={
                    "send_only_fails": send_only_fails,
                    "archive_previous_findings": archive_previous_findings,
                },
                credentials=credentials,
                provider_ids=[provider_id],
                enabled=enabled,
            )
        except Exception as e:
            self.logger.error(f"AWS Security Hub integration creation failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def create_jira_integration(
        self,
        domain: str = Field(
            description="Atlassian site name, without the '.atlassian.net' suffix. For the site 'https://acme.atlassian.net' the value is 'acme'. Full URLs are accepted and normalized automatically."
        ),
        user_mail: str = Field(
            description="Email address of the Atlassian account that owns the API token."
        ),
        api_token: str = Field(
            description="Atlassian API token, created from the account settings. It needs the 'read:jira-user', 'read:jira-work' and 'write:jira-work' scopes."
        ),
        enabled: bool = Field(
            default=True,
            description="Whether the integration starts enabled. Findings cannot be sent to a disabled Jira integration.",
        ),
    ) -> dict[str, Any]:
        """Create a Jira integration to open Jira work items from Prowler findings.

        Unlike the other integration types, Jira is tenant-wide: it is not attached to any
        provider and applies to every finding the role can see.

        IMPORTANT: Jira integrations do not send anything automatically. Work items are only
        created on demand with prowler_send_findings_to_jira.

        IMPORTANT: The connection is checked right after creation, and that check is what
        discovers the available Jira projects. If 'connected' comes back 'failed', the
        'projects' mapping stays empty and no finding can be dispatched.

        Default behavior:
        - The integration is created enabled
        - The configuration is entirely server-generated: 'domain', 'projects' and 'issue_types'

        Example Input:
        ```json
        {
            "domain": "acme",
            "user_mail": "security@acme.com",
            "api_token": "ATATT3xFfGF0..."
        }
        ```

        Workflow:
        1. Use this tool to create the integration
        2. Read 'projects' in the response configuration to pick a project key
        3. Use prowler_get_jira_issue_types with that project key to pick an issue type
        4. Use prowler_send_findings_to_jira to create the work items
        """
        try:
            normalized_domain = self._normalize_atlassian_domain(domain)
            self.logger.info(
                f"Creating Jira integration for domain {normalized_domain}..."
            )

            return await self._create_integration(
                integration_type="jira",
                # Jira rejects any configuration in the payload, the API generates it
                configuration={},
                credentials={
                    "domain": normalized_domain,
                    "user_mail": user_mail,
                    "api_token": api_token,
                },
                provider_ids=[],
                enabled=enabled,
            )
        except Exception as e:
            self.logger.error(f"Jira integration creation failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def update_integration(
        self,
        integration_id: str = Field(
            description="UUID of the integration to update. Use prowler_list_integrations to find it."
        ),
        enabled: bool | None = Field(
            default=None,
            description="Enable (True) or disable (False) the integration. If not specified, the enabled state remains unchanged.",
        ),
        provider_ids: list[str] | None = Field(
            default=None,
            description="Replace the providers this integration is attached to. Omit to keep the current ones. For 'amazon_s3' an empty list detaches every provider. For 'aws_security_hub' exactly one provider ID is required, since the integration cannot exist without one. Not accepted for Jira integrations, which are tenant-wide.",
        ),
        configuration: (
            dict[str, Any] | str | None
        ) = Field(  # `str` accepted due to bad MCP Clients implementation
            default=None,
            description="Integration-type specific settings to change. Only the keys provided are modified, the rest of the configuration is preserved. For 'amazon_s3': 'bucket_name', 'output_directory'. For 'aws_security_hub': 'send_only_fails', 'archive_previous_findings'. Not accepted for 'jira', whose configuration is entirely server-generated.",
        ),
        credentials: (
            dict[str, Any] | str | None
        ) = Field(  # `str` accepted due to bad MCP Clients implementation
            default=None,
            description="Replace the stored credentials. The whole object is replaced, so every needed key must be provided. For 'amazon_s3' and 'aws_security_hub': any of 'role_arn', 'external_id', 'role_session_name', 'session_duration', 'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'; an empty object clears them so Prowler falls back to the ambient or provider credentials. For 'jira': 'domain', 'user_mail' and 'api_token', all required, an empty or partial object is refused because it would destroy the stored credentials.",
        ),
    ) -> dict[str, Any]:
        """Update an integration's credentials, configuration, providers or enabled state.

        The integration type cannot be changed. To switch types, delete the integration and
        create a new one.

        Default behavior:
        - Only the parameters provided are changed, everything else is preserved
        - 'configuration' is merged with the current one, so partial updates are safe
        - When 'credentials', 'configuration' or the attached providers change, the connection
          is re-checked and the result is part of the response. Toggling only 'enabled' does
          not re-check it

        Constraints:
        - Jira integrations reject 'configuration' and 'provider_ids'. Sending a configuration
          would wipe the discovered 'projects' and 'issue_types', so this tool refuses it
        - Jira 'credentials' are replaced as a whole, so 'domain', 'user_mail' and 'api_token'
          are all required. An empty or partial object is refused because it would destroy the
          stored credentials
        - Security Hub integrations must keep exactly one AWS provider, so 'provider_ids' has
          to contain a single ID. Use prowler_delete_integration to stop sending findings
        - The 'enabled_regions' of a Security Hub integration are server-owned and cannot be
          set here, they are refreshed by the connection check

        Workflow:
        1. Use prowler_get_integration to read the current configuration
        2. Use this tool with only the fields to change
        3. Read 'connected' in the response to confirm the integration still works
        """
        self.logger.info(f"Updating integration {integration_id}...")

        try:
            current = DetailedIntegration.from_api_response(
                await self._get_integration_raw(integration_id)
            )
            integration_type = current.integration_type

            if provider_ids is not None:
                if integration_type == "jira":
                    raise ValueError(
                        "Jira integrations are tenant-wide and cannot be attached to providers."
                    )
                if integration_type == "aws_security_hub" and len(provider_ids) != 1:
                    raise ValueError(
                        "AWS Security Hub integrations must stay attached to exactly one AWS "
                        f"provider, got {len(provider_ids)}. Pass a single provider ID, or use "
                        "prowler_delete_integration to stop sending findings to Security Hub."
                    )

            attributes: dict[str, Any] = {}
            if enabled is not None:
                attributes["enabled"] = enabled

            if credentials is not None:
                attributes["credentials"] = self._validate_credentials(
                    integration_type, self._as_dict(credentials, "credentials")
                )

            if configuration is not None:
                if integration_type == "jira":
                    raise ValueError(
                        "Jira integrations do not accept a configuration: it is generated by Prowler. "
                        "Update the credentials instead, or run prowler_test_integration_connection to "
                        "refresh the available projects and issue types."
                    )
                merged = dict(current.configuration)
                merged.update(self._as_dict(configuration, "configuration"))
                # Server-owned, the API repopulates it from the connection check
                merged.pop("regions", None)
                merged.pop("enabled_regions", None)
                attributes["configuration"] = merged

            if not attributes and provider_ids is None:
                self.logger.info("No changes provided, returning the current state")
                return current.model_dump()

            update_body: dict[str, Any] = {
                "data": {
                    "type": "integrations",
                    "id": integration_id,
                    "attributes": attributes,
                }
            }
            if provider_ids is not None:
                update_body["data"]["relationships"] = _providers_relationship(
                    provider_ids
                )

            await self.api_client.patch(
                f"/integrations/{integration_id}", json_data=update_body
            )

            # A different provider means different effective credentials and different
            # discovered configuration, so the stored connection state is stale too
            providers_changed = provider_ids is not None and set(provider_ids) != set(
                current.provider_ids
            )
            recheck_connection = (
                credentials is not None
                or configuration is not None
                or providers_changed
            )
            connection_status = (
                await self._test_connection(integration_id)
                if recheck_connection
                else None
            )

            updated = await self._get_integration_raw(integration_id)
            if connection_status is not None:
                return IntegrationConnectionStatus.create(
                    updated, connection_status
                ).model_dump()
            return DetailedIntegration.from_api_response(updated).model_dump()
        except Exception as e:
            self.logger.error(f"Integration update failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def delete_integration(
        self,
        integration_id: str = Field(
            description="UUID of the integration to permanently remove. Use prowler_list_integrations to find it."
        ),
    ) -> dict[str, Any]:
        """Permanently remove an integration from Prowler.

        WARNING: This is a destructive operation that cannot be undone. The stored credentials
        are destroyed with it, so the integration has to be recreated from scratch, with its
        credentials, to be used again.

        Deletion behavior:
        - Prowler stops sending results to this destination immediately
        - Data already exported stays where it is: objects in S3, findings in Security Hub and
          work items in Jira are not removed
        - To pause an integration instead, use prowler_update_integration with enabled=False

        Workflow:
        1. Use prowler_get_integration to review what will be deleted
        2. Use this tool to permanently remove it
        3. Verify with prowler_list_integrations (it should no longer appear)
        """
        self.logger.info(f"Deleting integration {integration_id}...")

        try:
            await self.api_client.delete(f"/integrations/{integration_id}")
            return {
                "deleted": True,
                "message": f"Integration {integration_id} deleted successfully",
            }
        except Exception as e:
            self.logger.error(f"Integration deletion failed: {e}")
            return {
                "deleted": False,
                "message": f"Integration {integration_id} deletion failed: {str(e)}",
            }

    async def test_integration_connection(
        self,
        integration_id: str = Field(
            description="UUID of the integration to check. Use prowler_list_integrations to find it."
        ),
    ) -> dict[str, Any]:
        """Check that Prowler can reach an integration with its stored credentials.

        This also refreshes the parts of the configuration that Prowler discovers from the
        remote system, so it is the way to repair a stale configuration:
        - jira: repopulates 'projects' and 'issue_types'
        - aws_security_hub: repopulates 'enabled_regions'

        IMPORTANT: A disabled integration is never checked. It comes back as 'failed' with the
        error 'Integration is not enabled'. Enable it first with prowler_update_integration.

        The check runs as a background task and this tool waits for it, so it can take a few
        seconds to return.

        Workflow:
        1. Use prowler_list_integrations to spot integrations with connected=false
        2. Use this tool to re-check one after fixing its permissions on the remote side
        3. If it still fails, read 'error' and fix the credentials with prowler_update_integration
        """
        self.logger.info(f"Checking connection of integration {integration_id}...")

        connection_status = await self._test_connection(integration_id)
        integration = await self._get_integration_raw(integration_id)

        return IntegrationConnectionStatus.create(
            integration, connection_status
        ).model_dump()

    async def get_jira_issue_types(
        self,
        integration_id: str = Field(
            description="UUID of the Jira integration. Use prowler_list_integrations with integration_type=['jira'] to find it."
        ),
        project_key: str = Field(
            description="Key of the Jira project to read the issue types from (e.g. 'PROJ'). It must be one of the keys in the 'projects' mapping of the integration configuration."
        ),
    ) -> dict[str, Any]:
        """List the issue types available in a Jira project.

        Prowler fetches them live from Jira and stores them in the integration configuration,
        so the answer is always current.

        IMPORTANT: The project key must already be present in the 'projects' mapping of the
        integration configuration. That mapping is discovered by the connection check, so run
        prowler_test_integration_connection first if it is empty.

        NOTE: Issue types that require custom fields Prowler does not fill, such as Epic, will
        be listed here but fail when actually creating the work item. Prefer Task, Bug or Story.

        Workflow:
        1. Use prowler_get_integration to read the 'projects' mapping and pick a project key
        2. Use this tool to get the valid issue types for that project
        3. Use prowler_send_findings_to_jira with the chosen project key and issue type
        """
        self.logger.info(
            f"Fetching Jira issue types of project {project_key} for integration {integration_id}..."
        )

        api_response = await self.api_client.get(
            f"/integrations/{integration_id}/jira/issue_types",
            params={"project_key": project_key},
        )

        issue_types = JiraIssueTypes.from_api_response(api_response.get("data", {}))
        return issue_types.model_dump()

    async def send_findings_to_jira(
        self,
        integration_id: str = Field(
            description="UUID of the Jira integration to send the findings through. It must be enabled."
        ),
        project_key: str = Field(
            description="Key of the Jira project the work items are created in (e.g. 'PROJ'). It must be one of the keys in the 'projects' mapping of the integration configuration."
        ),
        issue_type: str = Field(
            description="Jira issue type for the created work items (e.g. 'Task', 'Bug', 'Story'). It must be one of the values returned by prowler_get_jira_issue_types for this project."
        ),
        finding_ids: list[str] = Field(
            description="UUIDs of the findings to send. One Jira work item is created per finding. Get them from prowler_search_security_findings. Must contain at least one ID."
        ),
    ) -> dict[str, Any]:
        """Create Jira work items for a set of findings.

        Each work item carries the finding's check title, severity, status, provider, region,
        resource, risk description and remediation steps.

        WARNING: This creates real work items in Jira. Prowler cannot delete or update them
        afterwards, they have to be handled in Jira. Only call this again for the same findings
        when the previous response had safe_to_retry=true, otherwise it creates duplicates.

        WARNING: Avoid issue types that require custom fields Prowler does not fill, such as
        Epic. Creation fails for those. Task, Bug and Story normally work.

        Default behavior:
        - One work item per finding, created sequentially, so large batches take a while
        - The dispatch runs as a background task and this tool waits up to 5 minutes for it.
          If it is still running by then, the response has status='in_progress', an 'error'
          explaining it, and the 'task_id'

        The result includes:
        - status: 'completed' when Prowler finished the dispatch, 'in_progress' when the task
          is still running, 'failed' when the dispatch was rejected before it started,
          'unknown' when the task stopped without reporting a result
        - safe_to_retry: whether the dispatch can be sent again. It is only true when no work
          item was created, which is the case when the dispatch was rejected before it
          started. NEVER call this tool again for the same findings when it is false, the
          work items already created would be duplicated. Report the outcome to the user and
          let them check Jira instead
        - created_count: number of work items created in Jira, absent unless status='completed'
        - failed_count: number of findings that could not be sent, absent unless
          status='completed'

        Workflow:
        1. Use prowler_search_security_findings to select the findings to escalate
        2. Use prowler_get_integration to read the 'projects' mapping and pick a project key
        3. Use prowler_get_jira_issue_types to pick a valid issue type
        4. Use this tool with the finding IDs
        """
        try:
            if not finding_ids:
                raise ValueError(
                    "At least one finding ID is required. Use prowler_search_security_findings to get them."
                )

            self.logger.info(
                f"Sending {len(finding_ids)} finding(s) to Jira project {project_key}..."
            )

            dispatch_body = {
                "data": {
                    "type": "integrations-jira-dispatches",
                    "attributes": {
                        "project_key": project_key,
                        "issue_type": issue_type,
                    },
                }
            }
            params = self.api_client.build_filter_params(
                {"filter[finding_id__in]": finding_ids}
            )

            task_response = await self.api_client.post(
                f"/integrations/{integration_id}/jira/dispatches",
                params=params,
                json_data=dispatch_body,
            )
        except ValueError as e:
            # Refused here, so the request never went out
            self.logger.error(f"Jira dispatch was refused before the request: {e}")
            return self._jira_dispatch_rejected(str(e))
        except ProwlerAPIError as e:
            # Only a client error is a refusal: the API validates the dispatch and
            # then queues the background task before serializing its answer, so a
            # server error may well come back with work items already being created
            if e.status_code >= 500:
                self.logger.error(f"Jira dispatch failed on the server: {e}")
                return self._jira_dispatch_unknown(
                    task_id=None,
                    error=(
                        f"the request that starts the dispatch failed on the server: {e} "
                        "It may have been queued anyway."
                    ),
                )

            self.logger.error(f"Jira dispatch was rejected by Prowler: {e}")
            return self._jira_dispatch_rejected(str(e))
        except Exception as e:
            # No answer came back, so the request may still have been accepted
            self.logger.error(f"Jira dispatch could not be started: {e}")
            return self._jira_dispatch_unknown(
                task_id=None,
                error=(
                    f"the request that starts the dispatch got no answer: {e} "
                    "It may have been accepted anyway."
                ),
            )

        task_id = task_response.get("data", {}).get("id")
        if not task_id:
            self.logger.error("Jira dispatch response did not include a task ID")
            return self._jira_dispatch_unknown(
                task_id=None,
                error="Prowler accepted the dispatch but did not return the ID of the background task, so its outcome cannot be checked.",
            )

        try:
            completed_task = await self.api_client.poll_task_until_complete(
                task_id=task_id, timeout=JIRA_DISPATCH_TIMEOUT, poll_interval=2.0
            )
        except Exception as e:
            self.logger.error(f"Jira dispatch did not complete cleanly: {e}")
            return await self._jira_dispatch_fallback(task_id, str(e))

        try:
            return JiraDispatchResult.from_task_result(
                completed_task.get("data", {}).get("attributes", {}).get("result")
            ).model_dump()
        except ValueError as e:
            self.logger.error(f"Jira dispatch result could not be read: {e}")
            return self._jira_dispatch_unknown(task_id, str(e))

    # Private helper methods

    def _build_aws_credentials(
        self,
        role_arn: str | None = None,
        external_id: str | None = None,
        role_session_name: str | None = None,
        session_duration: int | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
    ) -> dict[str, Any]:
        """Build the AWS credentials object, leaving out the values not provided.

        An empty result is valid: it makes Prowler fall back to the ambient AWS credentials
        of the deployment, or to the credentials stored for the provider in the case of
        Security Hub.
        """
        credentials = {
            "role_arn": role_arn,
            "external_id": external_id,
            "role_session_name": role_session_name,
            "session_duration": session_duration,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
            "aws_session_token": aws_session_token,
        }
        return {key: value for key, value in credentials.items() if value is not None}

    def _normalize_atlassian_domain(self, domain: str) -> str:
        """Reduce a Jira site URL to the bare Atlassian site name.

        The API only accepts the site name, so 'https://acme.atlassian.net/jira' has to be
        sent as 'acme'.
        """
        normalized = domain.strip()
        normalized = normalized.split("://", 1)[-1]
        normalized = normalized.split("/", 1)[0]
        normalized = normalized.removesuffix(".atlassian.net")

        if not normalized:
            raise ValueError(
                f"Invalid Jira domain: {domain}. Provide the Atlassian site name, for example "
                "'acme' for the site 'https://acme.atlassian.net'."
            )
        return normalized

    def _validate_credentials(
        self, integration_type: str, credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Check that replacing the credentials leaves the integration usable.

        The API replaces the stored credentials with whatever is sent, so an empty or partial
        object silently destroys them. That is only acceptable for the AWS integration types,
        where no credentials means falling back to the ambient or provider ones.
        """
        if integration_type != "jira":
            return credentials

        missing = [
            key
            for key in JIRA_REQUIRED_CREDENTIALS
            if not isinstance(credentials.get(key), str) or not credentials[key].strip()
        ]
        if missing:
            raise ValueError(
                "Jira credentials are replaced as a whole, so 'domain', 'user_mail' and "
                f"'api_token' are all required. Missing or empty: {', '.join(missing)}. "
                "Sending an incomplete object would destroy the stored credentials and break "
                "the integration."
            )

        return {
            **credentials,
            "domain": self._normalize_atlassian_domain(credentials["domain"]),
        }

    def _as_dict(self, value: dict[str, Any] | str, param_name: str) -> dict[str, Any]:
        """Accept a JSON object sent as a string by clients that cannot pass objects."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON for {param_name}: {e}")

        if not isinstance(value, dict):
            raise ValueError(f"{param_name} must be a JSON object.")
        return value

    async def _get_integration_raw(self, integration_id: str) -> dict[str, Any]:
        """Fetch the raw JSON:API resource of an integration.

        Raises:
            ValueError: If the payload does not contain a usable integration resource
        """
        response = await self.api_client.get(f"/integrations/{integration_id}")
        integration = response.get("data")

        if not isinstance(integration, dict) or not integration.get("id"):
            raise ValueError(
                f"Integration {integration_id} was not found. Use prowler_list_integrations "
                "to get a valid integration ID."
            )

        if not isinstance(integration.get("attributes"), dict):
            raise ValueError(
                f"Prowler returned integration {integration_id} without its attributes, so "
                "its state cannot be read."
            )

        return integration

    async def _create_integration(
        self,
        integration_type: str,
        configuration: dict[str, Any],
        credentials: dict[str, Any],
        provider_ids: list[str],
        enabled: bool,
    ) -> dict[str, Any]:
        """Create an integration and report the outcome of its connection check.

        The check is always run: for Jira and Security Hub it is what discovers the projects
        and the enabled regions, so without it the integration is not usable.
        """
        create_body: dict[str, Any] = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": integration_type,
                    "configuration": configuration,
                    "credentials": credentials,
                    "enabled": enabled,
                },
            }
        }
        if provider_ids:
            create_body["data"]["relationships"] = _providers_relationship(provider_ids)

        api_response = await self.api_client.post(
            "/integrations", json_data=create_body
        )
        integration_id = api_response.get("data", {}).get("id")

        if not integration_id:
            raise ValueError(
                "Prowler accepted the integration creation but did not return its ID, so the "
                "connection could not be checked. Use prowler_list_integrations to see whether "
                "the integration exists before creating it again."
            )

        connection_status = await self._test_connection(integration_id)

        try:
            integration = await self._get_integration_raw(integration_id)
        except Exception as e:
            # The integration exists, so surface its ID instead of a plain read failure
            raise ValueError(
                f"Integration {integration_id} was created, but reading its state failed: {e} "
                "Use prowler_get_integration with that ID to check it."
            ) from e

        return IntegrationConnectionStatus.create(
            integration, connection_status
        ).model_dump()

    async def _test_connection(self, integration_id: str) -> dict[str, Any]:
        """Run the connection check of an integration and wait for its result.

        A check that could not be run is reported as 'connected: None' rather than a failure:
        a disabled integration or wrong credentials come back as a completed task with
        'connected: False', so an exception here only means the outcome is unknown.

        Returns:
            Connection status dictionary with a 'connected' boolean or None, and an optional
            'error'
        """
        self.logger.info(f"Testing connection for integration {integration_id}...")
        try:
            task_response = await self.api_client.post(
                f"/integrations/{integration_id}/connection", json_data={}
            )
            task_id = task_response.get("data", {}).get("id")

            if not task_id:
                raise ValueError(
                    "Prowler did not return the ID of the connection check task."
                )

            completed_task = await self.api_client.poll_task_until_complete(
                task_id=task_id, timeout=CONNECTION_CHECK_TIMEOUT, poll_interval=1.0
            )
            result = completed_task.get("data", {}).get("attributes", {}).get("result")

            if not isinstance(result, dict):
                raise ValueError(
                    "The connection check task completed without reporting a result."
                )

            return result
        except Exception as e:
            self.logger.error(f"Connection check could not be completed: {e}")
            return {
                "connected": None,
                "error": (
                    f"The connection check could not be completed: {e} This says nothing "
                    "about the stored credentials, run prowler_test_integration_connection "
                    "to check them again."
                ),
            }

    async def _jira_dispatch_fallback(self, task_id: str, error: str) -> dict[str, Any]:
        """Report a Jira dispatch whose polling did not end on a completed task.

        The dispatch is never safe to retry here. Work items are created one by one, so a task
        that failed or was cancelled halfway may already have created some of them, and a task
        that is still running is creating them right now. The task state only decides how the
        outcome is described.
        """
        state = None
        try:
            task = await self.api_client.get(f"/tasks/{task_id}")
            state = task.get("data", {}).get("attributes", {}).get("state")
        except Exception as e:
            self.logger.error(f"Could not read the state of task {task_id}: {e}")

        if state in ("failed", "cancelled"):
            return self._jira_dispatch_unknown(
                task_id,
                f"The dispatch task ended as '{state}' before reporting a result. "
                f"Original error: {error}",
            )

        return JiraDispatchResult(
            status="in_progress",
            safe_to_retry=False,
            error=(
                f"The dispatch is still running, so some work items may already exist in Jira. "
                f"Do not send these findings again. Original error: {error}"
            ),
            task_id=task_id,
        ).model_dump()

    def _jira_dispatch_rejected(self, error: str) -> dict[str, Any]:
        """Report a dispatch that was refused before any work item could be created.

        This is the only outcome safe to retry, and it is reserved for the failures
        that prove nothing was queued: a validation error raised here, or a client
        error from the API, which rejects the dispatch before starting its task.
        """
        return JiraDispatchResult(
            status="failed", safe_to_retry=True, error=error
        ).model_dump()

    def _jira_dispatch_unknown(self, task_id: str | None, error: str) -> dict[str, Any]:
        """Report a dispatch whose outcome Prowler cannot determine.

        Work items are created one by one, so an outcome that cannot be read is never safe to
        retry: the dispatch may have created any number of them before stopping.
        """
        return JiraDispatchResult(
            status="unknown",
            safe_to_retry=False,
            error=(
                f"Prowler cannot tell how many Jira work items were created: {error} "
                "Check the Jira project before sending these findings again."
            ),
            task_id=task_id,
        ).model_dump()
