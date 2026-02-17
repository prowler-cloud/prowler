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

        # Prerequisites status
        # None = API failed, True = has data, False = no data
        self.has_mde_devices: Optional[bool] = None
        self.exposure_management_active: Optional[bool] = None

        # Track if tables don't exist (feature not enabled vs no data)
        self.mde_table_not_found: bool = False
        self.exposure_table_not_found: bool = False

        # Check data
        self.exposed_credentials_privileged_users: Optional[
            List[ExposedCredentialPrivilegedUser]
        ] = []

        loop = self._get_event_loop()
        try:
            # First verify prerequisites, then fetch check data
            (
                mde_result,
                exposure_result,
                self.exposed_credentials_privileged_users,
            ) = loop.run_until_complete(
                asyncio.gather(
                    self._check_mde_devices(),
                    self._check_exposure_management(),
                    self._get_exposed_credentials_privileged_users(),
                )
            )
            # Unpack results
            self.has_mde_devices, self.mde_table_not_found = mde_result
            self.exposure_management_active, self.exposure_table_not_found = (
                exposure_result
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

    async def _run_hunting_query(self, query: str) -> tuple[Optional[List[Dict]], bool]:
        """
        Execute an Advanced Hunting query using Microsoft Graph Security API.

        Args:
            query: The KQL (Kusto Query Language) query to execute.

        Returns:
            Tuple of (results, table_not_found):
            - results: List of result dictionaries, empty list if no results, or None if API call failed.
            - table_not_found: True if the query failed because table doesn't exist (feature not enabled).
        """
        try:
            request_body = RunHuntingQueryPostRequestBody(query=query)
            response = await self.client.security.microsoft_graph_security_run_hunting_query.post(
                request_body
            )

            if not response or not response.results:
                return [], False

            results = [
                row.additional_data
                for row in response.results
                if hasattr(row, "additional_data")
            ]
            return results, False

        except Exception as error:
            error_message = str(error).lower()

            # Check if error is "table not found" - this means the feature is not enabled
            if (
                "failed to resolve table" in error_message
                or "could not find table" in error_message
            ):
                logger.warning(
                    f"DefenderXDR - Table not found in query, feature may not be enabled: {error}"
                )
                return [], True

            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None, False

    async def _check_mde_devices(self) -> tuple[Optional[bool], bool]:
        """
        Check if Microsoft Defender for Endpoint has devices reporting.

        Returns:
            Tuple of (has_devices, table_not_found):
            - has_devices: True if devices exist, False if no devices, None if API call failed.
            - table_not_found: True if DeviceInfo table doesn't exist (MDE not enabled).
        """
        logger.info("DefenderXDR - Checking for MDE devices...")

        query = "DeviceInfo | summarize DeviceCount = count()"
        results, table_not_found = await self._run_hunting_query(query)

        if results is None:
            return None, False

        if table_not_found:
            return False, True

        if results and len(results) > 0:
            device_count = results[0].get("DeviceCount", 0)
            return device_count > 0, False

        return False, False

    async def _check_exposure_management(self) -> tuple[Optional[bool], bool]:
        """
        Check if Security Exposure Management is active and has data.

        Returns:
            Tuple of (has_data, table_not_found):
            - has_data: True if has data, False if no data, None if API call failed.
            - table_not_found: True if ExposureGraphEdges table doesn't exist.
        """
        logger.info("DefenderXDR - Checking Exposure Management status...")

        query = "ExposureGraphEdges | take 1"
        results, table_not_found = await self._run_hunting_query(query)

        if results is None:
            return None, False

        if table_not_found:
            return False, True

        return len(results) > 0, False

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

        results, _ = await self._run_hunting_query(query)

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
