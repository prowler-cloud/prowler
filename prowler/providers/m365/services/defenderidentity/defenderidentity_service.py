"""Microsoft Defender for Identity service module.

This module provides the DefenderIdentity service class for interacting with
Microsoft Defender for Identity (MDI) through the Microsoft Graph API.
"""

import asyncio
from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class DefenderIdentity(M365Service):
    """Microsoft Defender for Identity service class.

    This class provides methods to retrieve and manage Microsoft Defender for Identity
    health issues, which monitor the health status of MDI configuration and sensors.

    Attributes:
        health_issues (list[HealthIssue]): List of health issues from MDI.
    """

    def __init__(self, provider: M365Provider):
        """Initialize the DefenderIdentity service client.

        Args:
            provider: The M365Provider instance for authentication and configuration.
        """
        super().__init__(provider)
        self.health_issues: List[HealthIssue] = []

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
                "Cannot initialize DefenderIdentity service while event loop is running"
            )

        self.health_issues = loop.run_until_complete(self._get_health_issues())

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

    async def _get_health_issues(self) -> List["HealthIssue"]:
        """Retrieve health issues from Microsoft Defender for Identity.

        This method fetches all health issues from the MDI deployment including
        both global and sensor-specific health alerts.

        Returns:
            List[HealthIssue]: A list of health issues from MDI.
        """
        logger.info("M365 - Getting Defender for Identity health issues...")
        health_issues = []
        try:
            health_issues_response = (
                await self.client.security.identities.health_issues.get()
            )

            while health_issues_response:
                for issue in getattr(health_issues_response, "value", []) or []:
                    health_issues.append(
                        HealthIssue(
                            id=getattr(issue, "id", ""),
                            display_name=getattr(issue, "display_name", ""),
                            description=getattr(issue, "description", ""),
                            health_issue_type=getattr(issue, "health_issue_type", None),
                            severity=getattr(issue, "severity", None),
                            status=getattr(issue, "status", None),
                            created_date_time=str(
                                getattr(issue, "created_date_time", "")
                            ),
                            last_modified_date_time=str(
                                getattr(issue, "last_modified_date_time", "")
                            ),
                            domain_names=getattr(issue, "domain_names", []) or [],
                            sensor_dns_names=getattr(issue, "sensor_d_n_s_names", [])
                            or [],
                            issue_type_id=getattr(issue, "issue_type_id", ""),
                            recommendations=getattr(issue, "recommendations", []) or [],
                            additional_information=getattr(
                                issue, "additional_information", []
                            )
                            or [],
                        )
                    )

                next_link = getattr(health_issues_response, "odata_next_link", None)
                if not next_link:
                    break
                health_issues_response = (
                    await self.client.security.identities.health_issues.with_url(
                        next_link
                    ).get()
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return health_issues


class HealthIssue(BaseModel):
    """Model for Microsoft Defender for Identity health issue.

    Attributes:
        id: The unique identifier for the health issue.
        display_name: The display name of the health issue.
        description: A detailed description of the health issue.
        health_issue_type: The type of health issue (global or sensor).
        severity: The severity level of the issue (low, medium, high).
        status: The current status of the issue (open, closed).
        created_date_time: When the issue was created.
        last_modified_date_time: When the issue was last modified.
        domain_names: List of domain names affected by the issue.
        sensor_dns_names: List of sensor DNS names affected by the issue.
        issue_type_id: The type identifier for the issue.
        recommendations: List of recommended actions to resolve the issue.
        additional_information: Additional information about the issue.
    """

    id: str
    display_name: str
    description: str
    health_issue_type: Optional[str]
    severity: Optional[str]
    status: Optional[str]
    created_date_time: str
    last_modified_date_time: str
    domain_names: List[str]
    sensor_dns_names: List[str]
    issue_type_id: str
    recommendations: List[str]
    additional_information: List[str]
