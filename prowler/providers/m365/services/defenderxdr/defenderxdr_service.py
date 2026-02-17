"""
Microsoft Defender XDR service for Prowler.

This module provides access to Microsoft Defender XDR Advanced Hunting API
through the Microsoft Graph Security API for exposure management checks.
"""

import asyncio
import json
from typing import Dict, List, Optional

from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import (
    RunHuntingQueryPostRequestBody,
)
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class DefenderXDR(M365Service):
    """
    Microsoft Defender XDR service class.

    Provides access to Microsoft Defender XDR Advanced Hunting API
    for security exposure management checks.
    """

    def __init__(self, provider: M365Provider):
        super().__init__(provider)

        self.exposed_credentials_privileged_users: Optional[
            List[ExposedCredentialPrivilegedUser]
        ] = []

        loop = self._get_event_loop()
        try:
            self.exposed_credentials_privileged_users = loop.run_until_complete(
                self._get_exposed_credentials_privileged_users()
            )
        finally:
            self._cleanup_event_loop(loop)

    def _get_event_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create an event loop for async operations."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                raise RuntimeError(
                    "Cannot initialize DefenderXDR service while event loop is running"
                )
            return loop
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop

    def _cleanup_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Clean up the event loop if we created it."""
        try:
            if loop and not loop.is_running():
                asyncio.set_event_loop(None)
                loop.close()
        except Exception:
            pass

    async def _run_hunting_query(self, query: str) -> Optional[List[Dict]]:
        """
        Execute an Advanced Hunting query using Microsoft Graph Security API.

        Args:
            query: The KQL (Kusto Query Language) query to execute.

        Returns:
            List of result dictionaries, empty list if no results, or None if API call failed.
        """
        try:
            request_body = RunHuntingQueryPostRequestBody(query=query)
            response = await self.client.security.microsoft_graph_security_run_hunting_query.post(
                request_body
            )

            if not response or not response.results:
                return []

            return [
                row.additional_data
                for row in response.results
                if hasattr(row, "additional_data")
            ]

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

        Returns:
            List of ExposedCredentialPrivilegedUser objects, or None if API call failed.
        """
        logger.info(
            "DefenderXDR - Querying for exposed credentials of privileged users..."
        )

        query = """
ExposureGraphEdges
| where EdgeLabel == "hasCredentialsFor"
| where TargetNodeLabel == "user"
| extend targetCategories = parse_json(TargetNodeCategories)
| where targetCategories has "PrivilegedEntraIdRole" or targetCategories has "privileged"
| extend credentialType = tostring(parse_json(EdgeProperties).credentialType)
| project
    EdgeId,
    SourceNodeId,
    SourceNodeName,
    SourceNodeLabel,
    TargetNodeId,
    TargetNodeName,
    TargetNodeLabel,
    CredentialType = credentialType,
    TargetCategories = TargetNodeCategories
"""

        results = await self._run_hunting_query(query)

        if results is None:
            return None

        return [self._parse_exposed_credential(row) for row in results if row]

    def _parse_exposed_credential(self, row: Dict) -> "ExposedCredentialPrivilegedUser":
        """Parse a single row from the hunting query into an ExposedCredentialPrivilegedUser."""
        target_categories = row.get("TargetCategories", [])

        if isinstance(target_categories, str):
            try:
                target_categories = json.loads(target_categories)
            except (json.JSONDecodeError, ValueError):
                target_categories = []

        return ExposedCredentialPrivilegedUser(
            edge_id=str(row.get("EdgeId", "")),
            source_node_id=str(row.get("SourceNodeId", "")),
            source_node_name=str(row.get("SourceNodeName", "Unknown")),
            source_node_label=str(row.get("SourceNodeLabel", "")),
            target_node_id=str(row.get("TargetNodeId", "")),
            target_node_name=str(row.get("TargetNodeName", "Unknown")),
            target_node_label=str(row.get("TargetNodeLabel", "")),
            credential_type=str(row.get("CredentialType") or "Unknown"),
            target_categories=target_categories,
        )


class ExposedCredentialPrivilegedUser(BaseModel):
    """
    Model for exposed credential data of a privileged user.

    Represents authentication credentials (CLI secrets, user cookies, tokens)
    of privileged users that are exposed on vulnerable endpoints.
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
