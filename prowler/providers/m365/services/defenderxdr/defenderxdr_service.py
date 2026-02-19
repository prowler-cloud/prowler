"""Microsoft Defender XDR service module.

This module provides access to Microsoft Defender XDR data
through the Microsoft Graph Security Advanced Hunting API.
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
    """Microsoft Defender XDR service class.

    Provides access to Microsoft Defender XDR data through
    the Microsoft Graph Security Advanced Hunting API.

    This class handles endpoint security checks including:
    - Device security posture
    - Exposed credentials detection
    - Vulnerability assessments
    - Critical Asset Management approvals

    Attributes:
        mde_status: Status of MDE deployment
            (None, "not_enabled", "no_devices", "active")
        exposed_credentials_privileged_users: List of privileged users
            with exposed credentials
        pending_cam_approvals: List of pending Critical Asset Management
            approvals (None if API error)
    """

    def __init__(self, provider: M365Provider):
        """Initialize the DefenderXDR service client.

        Args:
            provider: The M365Provider instance for authentication.
        """
        super().__init__(provider)

        # MDE status: None = API error, "not_enabled" = table not found,
        # "no_devices" = enabled but empty, "active" = has devices
        self.mde_status: Optional[str] = None

        # Check data
        self.exposed_credentials_privileged_users: Optional[
            List[ExposedCredentialPrivilegedUser]
        ] = []
        self.pending_cam_approvals: Optional[List[PendingCAMApproval]] = []

        loop = self._get_event_loop()
        try:
            (
                self.mde_status,
                self.exposed_credentials_privileged_users,
                self.pending_cam_approvals,
            ) = loop.run_until_complete(
                asyncio.gather(
                    self._check_mde_status(),
                    self._get_exposed_credentials_privileged_users(),
                    self._get_pending_cam_approvals(),
                )
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
        """Execute an Advanced Hunting query using Microsoft Graph Security API.

        Args:
            query: The KQL (Kusto Query Language) query to execute.

        Returns:
            Tuple of (results, table_not_found):
            - results: List of result dicts, empty list if no results,
              None if API error.
            - table_not_found: True if query failed because table
              doesn't exist.
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

            if (
                "failed to resolve table" in error_message
                or "could not find table" in error_message
            ):
                logger.warning(f"DefenderXDR - Table not found in query: {error}")
                return [], True

            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None, False

    async def _check_mde_status(self) -> Optional[str]:
        """Check Microsoft Defender for Endpoint status.

        Returns:
            - None: API call failed (permission issue)
            - "not_enabled": DeviceInfo table doesn't exist (MDE not enabled)
            - "no_devices": MDE enabled but no devices onboarded
            - "active": MDE enabled with devices reporting
        """
        logger.info("DefenderXDR - Checking MDE status...")

        query = "DeviceInfo | summarize DeviceCount = count()"
        results, table_not_found = await self._run_hunting_query(query)

        if results is None:
            return None

        if table_not_found:
            return "not_enabled"

        if results and len(results) > 0:
            device_count = results[0].get("DeviceCount", 0)
            if device_count > 0:
                return "active"

        return "no_devices"

    async def _get_exposed_credentials_privileged_users(
        self,
    ) -> Optional[List["ExposedCredentialPrivilegedUser"]]:
        """Query for privileged users with exposed credentials.

        Returns:
            List of ExposedCredentialPrivilegedUser objects,
            or None if API call failed.
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
        """Parse a single row into an ExposedCredentialPrivilegedUser."""
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

    async def _get_pending_cam_approvals(
        self,
    ) -> Optional[List["PendingCAMApproval"]]:
        """Query for pending Critical Asset Management approvals.

        Queries the ExposureGraphNodes table to find assets with low criticality
        confidence scores that require administrator approval.

        Returns:
            List of PendingCAMApproval objects, or None if API call failed.
        """
        logger.info(
            "DefenderXDR - Querying for pending Critical Asset Management approvals..."
        )

        query = """
ExposureGraphNodes
| where isnotempty(parse_json(NodeProperties)['rawData']['criticalityConfidenceLow'])
| mv-expand parse_json(NodeProperties)['rawData']['criticalityConfidenceLow']
| extend Classification = tostring(NodeProperties_rawData_criticalityConfidenceLow)
| summarize PendingApproval = count(), Assets = array_sort_asc(make_set(NodeName)) by Classification
| sort by Classification asc
"""

        results, _ = await self._run_hunting_query(query)

        if results is None:
            return None

        pending_approvals = []
        for row in results:
            if not row:
                continue
            classification = row.get("Classification", "")
            pending_count = int(row.get("PendingApproval", 0))
            assets_raw = row.get("Assets", "[]")

            if isinstance(assets_raw, str):
                try:
                    assets = json.loads(assets_raw)
                except (json.JSONDecodeError, ValueError):
                    assets = []
            elif isinstance(assets_raw, list):
                assets = assets_raw
            else:
                assets = []

            pending_approvals.append(
                PendingCAMApproval(
                    classification=classification,
                    pending_count=pending_count,
                    assets=assets,
                )
            )

        return pending_approvals


class ExposedCredentialPrivilegedUser(BaseModel):
    """Model for exposed credential data of a privileged user.

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


class PendingCAMApproval(BaseModel):
    """Model for a pending Critical Asset Management approval classification.

    Represents assets with low criticality confidence scores that require
    security administrator review and approval.

    Attributes:
        classification: The asset classification name pending approval.
        pending_count: The number of assets pending approval for this classification.
        assets: List of asset names pending approval.
    """

    classification: str
    pending_count: int
    assets: List[str]
