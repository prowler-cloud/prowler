"""Attack Paths tools for Prowler App MCP Server.

This module provides tools for analyzing Attack Paths data from Neo4j graph database.
Attack Paths help identify security risks by tracing potential attack vectors
through cloud infrastructure relationships.
"""

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.attack_paths import (
    AttackPathQuery,
    AttackPathQueryResult,
    AttackPathScansListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class AttackPathsTools(BaseTool):
    """Tools for Attack Paths analysis.

    Provides tools for:
    - prowler_app_list_attack_paths_scans: Find completed scans ready for analysis
    - prowler_app_list_attack_paths_queries: Discover available queries for a scan
    - prowler_app_run_attack_paths_query: Execute query and analyze attack paths
    """

    async def list_attack_paths_scans(
        self,
        provider_id: list[str] = Field(
            default=[],
            description="Filter by Prowler's internal UUID(s) (v4) for specific provider(s). Use `prowler_app_search_providers` tool to find provider IDs",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by cloud provider type (aws, azure, gcp, etc.). Use `prowler_hub_list_providers` to see supported provider types",
        ),
        state: list[
            Literal[
                "available",
                "scheduled",
                "executing",
                "completed",
                "failed",
                "cancelled",
            ]
        ] = Field(
            default=["completed"],
            description="Filter by scan execution state. Default: ['completed'] to show scans ready for analysis",
        ),
        page_size: int = Field(
            default=50,
            description="Number of results to return per page",
        ),
        page_number: int = Field(
            default=1,
            description="Page number to retrieve (1-indexed)",
        ),
    ) -> dict[str, Any]:
        """List Attack Paths scans with filtering capabilities.

        Default behavior:
        - Returns COMPLETED scans (ready for attack paths analysis)
        - Returns 50 scans per page
        - Shows the latest scan per provider

        Each scan includes:
        - Core identification: id (UUID for get/query operations)
        - Execution context: state, progress
        - Provider info: provider_id, provider_alias, provider_type, provider_uid

        Workflow:
        1. Use this tool to find completed attack paths scans
        2. Use prowler_app_list_attack_paths_queries to see available queries for a scan
        3. Use prowler_app_run_attack_paths_query to execute analysis
        """
        try:
            # Validate pagination
            self.api_client.validate_page_size(page_size)

            # Build query parameters
            params: dict[str, Any] = {
                "page[size]": page_size,
                "page[number]": page_number,
            }

            # Apply provider filters
            if provider_id:
                params["filter[provider__in]"] = provider_id
            if provider_type:
                params["filter[provider_type__in]"] = provider_type

            # Apply state filter
            if state:
                params["filter[state__in]"] = state

            clean_params = self.api_client.build_filter_params(params)

            api_response = await self.api_client.get(
                "/attack-paths-scans", params=clean_params
            )
            simplified_response = AttackPathScansListResponse.from_api_response(
                api_response
            )

            return simplified_response.model_dump()
        except Exception as e:
            self.logger.error(f"Failed to list attack paths scans: {e}")
            return {"error": f"Failed to list attack paths scans: {str(e)}"}

    async def list_attack_paths_queries(
        self,
        scan_id: str = Field(
            description="UUID of a COMPLETED attack paths scan. Use `prowler_app_list_attack_paths_scans` with state=['completed'] to find scan IDs"
        ),
    ) -> list[dict[str, Any]]:
        """Discover available Attack Paths queries for a completed scan.

        IMPORTANT: The scan must be in 'completed' state to list queries.
        Queries are provider-specific

        Each query includes:
        - id: Query identifier to use with run_attack_paths_query
        - name: Human-readable name describing what the query finds
        - description: Detailed explanation of the security analysis
        - parameters: List of required parameters (if any)

        Example queries (AWS):
        - aws-internet-exposed-ec2-sensitive-s3-access: Find EC2 instances exposed to internet with access to sensitive S3 buckets
        - aws-iam-privesc-passrole-ec2: Detect privilege escalation via PassRole + EC2
        - aws-ec2-instances-internet-exposed: Find internet-exposed EC2 instances

        Workflow:
        1. Use prowler_app_list_attack_paths_scans to find a completed scan
        2. Use this tool to discover available queries
        3. Use prowler_app_run_attack_paths_query with query_id and any required parameters
        """
        try:
            api_response = await self.api_client.get(
                f"/attack-paths-scans/{scan_id}/queries"
            )

            return [
                AttackPathQuery.from_api_response(query).model_dump()
                for query in api_response.get("data", [])
            ]
        except Exception as e:
            self.logger.error(
                f"Failed to list attack paths queries for scan {scan_id}: {e}"
            )
            return [{"error": f"Failed to list attack paths queries: {str(e)}"}]

    async def run_attack_paths_query(
        self,
        scan_id: str = Field(
            description="UUID of a COMPLETED attack paths scan. The scan must be in 'completed' state"
        ),
        query_id: str = Field(
            description="Query ID to execute (e.g., 'aws-internet-exposed-ec2-sensitive-s3-access'). Use `prowler_app_list_attack_paths_queries` to discover available queries"
        ),
        parameters: dict[str, str] = Field(
            default_factory=dict,
            description="Query parameters as key-value pairs. Check query definition for required parameters. Example: {'tag_key': 'DataClassification', 'tag_value': 'Sensitive'}",
        ),
    ) -> dict[str, Any]:
        """Execute an Attack Paths query and analyze the results.

        IMPORTANT: This is the PRIMARY tool for attack paths analysis.
        It executes a Cypher query against the Neo4j graph database and returns
        the attack path graph with security findings.

        Prerequisites:
        - Scan must be in 'completed' state
        - query_id must be valid for the scan's provider type
        - All required parameters must be provided

        Returns:
        - nodes: Cloud resources, findings, and virtual nodes in the attack path
        - relationships: Connections between nodes (CAN_ACCESS, STS_ASSUMEROLE_ALLOW, etc.)

        Node types you may see:
        - EC2Instance, S3Bucket, RDSInstance, LoadBalancer, etc. (cloud resources)
        - ProwlerFinding (security issues with severity and status)
        - Internet (virtual node representing external access)
        - PrivilegeEscalation (virtual node for escalation outcomes)

        Relationship types:
        - CAN_ACCESS: Network access path (often from Internet)
        - STS_ASSUMEROLE_ALLOW: IAM role assumption
        - MEMBER_OF_EC2_SECURITY_GROUP: Security group membership
        - And many more cloud-specific relationships

        Workflow:
        1. Ensure scan is completed
        2. List available queries (use prowler_app_list_attack_paths_queries)
        3. Execute this tool with appropriate parameters
        4. Analyze the returned graph for security insights
        """
        try:
            # Build the request payload following JSON:API format
            request_data: dict[str, Any] = {
                "data": {
                    "type": "attack-paths-query-run-requests",
                    "attributes": {
                        "id": query_id,
                    },
                },
            }

            # Add parameters if provided
            if parameters:
                request_data["data"]["attributes"]["parameters"] = parameters

            api_response = await self.api_client.post(
                f"/attack-paths-scans/{scan_id}/queries/run",
                json_data=request_data,
            )

            # Parse the response
            query_result = AttackPathQueryResult.from_api_response(api_response)

            return query_result.model_dump()
        except Exception as e:
            self.logger.error(
                f"Failed to run attack paths query '{query_id}' on scan {scan_id}: {e}"
            )
            return {"error": f"Failed to run attack paths query '{query_id}': {str(e)}"}
