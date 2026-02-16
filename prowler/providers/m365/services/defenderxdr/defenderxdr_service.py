"""
Microsoft Defender XDR service for Prowler.

This module provides access to Microsoft Defender XDR Advanced Hunting API
through the Microsoft Graph Security API for exposure management checks.
"""

import asyncio
import json
from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider

# fmt: off
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody  # noqa: E501
# fmt: on


class DefenderXDR(M365Service):
    """
    Microsoft Defender XDR service class.

    This class provides methods to retrieve security exposure data from
    Microsoft Defender XDR using the Advanced Hunting API. It enables
    querying the ExposureGraphEdges table to identify security risks
    such as exposed credentials for privileged users.

    Attributes:
        exposed_credentials_privileged_users (list): List of privileged users
            with exposed credentials on vulnerable endpoints.
    """

    def __init__(self, provider: M365Provider):
        """
        Initialize the DefenderXDR service client.

        Args:
            provider: The M365Provider instance for authentication and configuration.
        """
        super().__init__(provider)
        self.exposed_credentials_privileged_users: Optional[
            List[ExposedCredentialPrivilegedUser]
        ] = []

        created_loop = False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created_loop = True

        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created_loop = True

        if loop.is_running():
            raise RuntimeError(
                "Cannot initialize DefenderXDR service while event loop is running"
            )

        self.exposed_credentials_privileged_users = loop.run_until_complete(
            self._get_exposed_credentials_privileged_users()
        )

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

    async def _run_advanced_hunting_query(self, query: str) -> Optional[list]:
        """
        Execute an Advanced Hunting query using Microsoft Graph Security API.

        Args:
            query: The KQL (Kusto Query Language) query to execute.

        Returns:
            Optional[list]: A list of results from the query, or None if the API call failed.
        """
        try:
            request_body = RunHuntingQueryPostRequestBody(
                query=query,
            )

            result = await self.client.security.microsoft_graph_security_run_hunting_query.post(
                request_body
            )

            if result and result.results:
                return result.results
            return []
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    async def _get_exposed_credentials_privileged_users(
        self,
    ) -> Optional[List["ExposedCredentialPrivilegedUser"]]:
        """
        Query for privileged users with exposed credentials on vulnerable endpoints.

        This method queries the ExposureGraphEdges table to find privileged users
        whose authentication artifacts (CLI secrets, user cookies, sensitive tokens)
        are exposed on endpoints with high risk or exposure scores.

        Returns:
            Optional[List[ExposedCredentialPrivilegedUser]]: A list of exposed credential
                objects, or None if the API call failed.
        """
        logger.info("M365 - Querying for exposed credentials of privileged users...")
        exposed_users: List[ExposedCredentialPrivilegedUser] = []
        try:
            # KQL query to find exposed credentials for privileged users
            # This query finds edges where:
            # 1. The edge represents exposed credentials (hasCredentialsFor relationship)
            # 2. The target is a privileged user with Entra ID roles
            # 3. The source is a device with high risk/exposure score
            query = """
ExposureGraphEdges
| where EdgeLabel == "hasCredentialsFor"
| where TargetNodeLabel == "user"
| extend targetCategories = parse_json(TargetNodeCategories)
| where targetCategories has "PrivilegedEntraIdRole" or targetCategories has "privileged"
| extend edgeProps = parse_json(EdgeProperties)
| extend credentialType = tostring(edgeProps.credentialType)
| extend sourceProps = parse_json(SourceNodeCategories)
| project
    EdgeId,
    SourceNodeId,
    SourceNodeName,
    SourceNodeLabel,
    TargetNodeId,
    TargetNodeName,
    TargetNodeLabel,
    CredentialType = credentialType,
    TargetCategories = TargetNodeCategories,
    EdgeProperties
"""
            results = await self._run_advanced_hunting_query(query)

            # If query failed, propagate None
            if results is None:
                return None

            for result in results:
                if isinstance(result, dict):
                    credential_type = result.get("CredentialType", "Unknown")
                    target_categories = result.get("TargetCategories", [])

                    # Parse categories if it's a string
                    if isinstance(target_categories, str):
                        try:
                            target_categories = json.loads(target_categories)
                        except (json.JSONDecodeError, ValueError):
                            target_categories = []

                    exposed_users.append(
                        ExposedCredentialPrivilegedUser(
                            edge_id=result.get("EdgeId", ""),
                            source_node_id=result.get("SourceNodeId", ""),
                            source_node_name=result.get("SourceNodeName", "Unknown"),
                            source_node_label=result.get("SourceNodeLabel", ""),
                            target_node_id=result.get("TargetNodeId", ""),
                            target_node_name=result.get("TargetNodeName", "Unknown"),
                            target_node_label=result.get("TargetNodeLabel", ""),
                            credential_type=credential_type,
                            target_categories=target_categories,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

        return exposed_users


class ExposedCredentialPrivilegedUser(BaseModel):
    """
    Model for exposed credential data of a privileged user.

    Represents authentication credentials (CLI secrets, user cookies, tokens)
    of privileged users that are exposed on vulnerable endpoints.

    Attributes:
        edge_id: Unique identifier for the exposure relationship.
        source_node_id: ID of the device/endpoint where credentials are exposed.
        source_node_name: Name of the device/endpoint.
        source_node_label: Label/type of the source node (e.g., "device").
        target_node_id: ID of the privileged user whose credentials are exposed.
        target_node_name: Name/UPN of the privileged user.
        target_node_label: Label/type of the target node (e.g., "user").
        credential_type: Type of exposed credential (e.g., "CLI secret", "cookie").
        target_categories: List of categories for the target user.
    """

    edge_id: str
    source_node_id: str
    source_node_name: str
    source_node_label: str
    target_node_id: str
    target_node_name: str
    target_node_label: str
    credential_type: Optional[str] = None
    target_categories: list = []
