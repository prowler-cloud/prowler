"""Microsoft Defender for Identity service module.

This module provides the DefenderIdentity service class for interacting with
Microsoft Defender for Identity (MDI) APIs, including health issues and sensors.
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
        sensors (list[Sensor]): List of sensors from MDI.
    """

    def __init__(self, provider: M365Provider):
        """Initialize the DefenderIdentity service client.

        Args:
            provider: The M365Provider instance for authentication and configuration.
        """
        super().__init__(provider)
        self.sensors: Optional[List[Sensor]] = []
        self.health_issues: Optional[List[HealthIssue]] = []

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

        self.sensors = loop.run_until_complete(self._get_sensors())
        self.health_issues = loop.run_until_complete(self._get_health_issues())

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

    async def _get_sensors(self) -> Optional[List["Sensor"]]:
        """Retrieve sensors from Microsoft Defender for Identity.

        This method fetches all MDI sensors deployed in the environment,
        including their health status and configuration.

        Returns:
            Optional[List[Sensor]]: A list of sensors from MDI,
                or None if the API call failed (tenant not onboarded or missing permissions).
        """
        logger.info("DefenderIdentity - Getting sensors...")
        sensors: Optional[List[Sensor]] = []

        # Step 1: Call the API
        try:
            sensors_response = await self.client.security.identities.sensors.get()
        except Exception as error:
            error_msg = str(error)
            if "403" in error_msg or "Forbidden" in error_msg:
                logger.error(
                    "DefenderIdentity - Permission denied accessing sensors API. "
                    "Ensure the Service Principal has SecurityIdentitiesSensors.Read.All permission."
                )
            elif "401" in error_msg or "Unauthorized" in error_msg:
                logger.error(
                    "DefenderIdentity - Authentication failed accessing sensors API. "
                    "Verify the Service Principal credentials are valid."
                )
            else:
                logger.error(
                    f"DefenderIdentity - API error getting sensors: "
                    f"{error.__class__.__name__}: {error}"
                )
            return None

        # Step 2: Parse the response
        try:
            while sensors_response:
                for sensor in getattr(sensors_response, "value", []) or []:
                    sensors.append(
                        Sensor(
                            id=getattr(sensor, "id", ""),
                            display_name=getattr(sensor, "display_name", ""),
                            sensor_type=(
                                str(getattr(sensor, "sensor_type", ""))
                                if getattr(sensor, "sensor_type", None)
                                else None
                            ),
                            deployment_status=(
                                str(getattr(sensor, "deployment_status", ""))
                                if getattr(sensor, "deployment_status", None)
                                else None
                            ),
                            health_status=(
                                str(getattr(sensor, "health_status", ""))
                                if getattr(sensor, "health_status", None)
                                else None
                            ),
                            open_health_issues_count=getattr(
                                sensor, "open_health_issues_count", 0
                            )
                            or 0,
                            domain_name=getattr(sensor, "domain_name", ""),
                            version=getattr(sensor, "version", ""),
                            created_date_time=str(
                                getattr(sensor, "created_date_time", "")
                            ),
                        )
                    )

                next_link = getattr(sensors_response, "odata_next_link", None)
                if not next_link:
                    break
                sensors_response = (
                    await self.client.security.identities.sensors.with_url(
                        next_link
                    ).get()
                )
        except Exception as error:
            logger.error(
                f"DefenderIdentity - Error parsing sensors response: "
                f"{error.__class__.__name__}: {error}"
            )
            return None

        return sensors

    async def _get_health_issues(self) -> Optional[List["HealthIssue"]]:
        """Retrieve health issues from Microsoft Defender for Identity.

        This method fetches all health issues from the MDI deployment including
        both global and sensor-specific health alerts.

        Returns:
            Optional[List[HealthIssue]]: A list of health issues from MDI,
                or None if the API call failed (tenant not onboarded or missing permissions).
        """
        logger.info("DefenderIdentity - Getting health issues...")
        health_issues: Optional[List[HealthIssue]] = []

        # Step 1: Call the API
        try:
            health_issues_response = (
                await self.client.security.identities.health_issues.get()
            )
        except Exception as error:
            error_msg = str(error)
            if "403" in error_msg or "Forbidden" in error_msg:
                logger.error(
                    "DefenderIdentity - Permission denied accessing health issues API. "
                    "Ensure the Service Principal has SecurityIdentitiesHealth.Read.All permission."
                )
            elif "401" in error_msg or "Unauthorized" in error_msg:
                logger.error(
                    "DefenderIdentity - Authentication failed accessing health issues API. "
                    "Verify the Service Principal credentials are valid."
                )
            else:
                logger.error(
                    f"DefenderIdentity - API error getting health issues: "
                    f"{error.__class__.__name__}: {error}"
                )
            return None

        # Step 2: Parse the response
        try:
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
                            issue_type_id=getattr(issue, "issue_type_id", None),
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
                f"DefenderIdentity - Error parsing health issues response: "
                f"{error.__class__.__name__}: {error}"
            )
            return None

        return health_issues


class Sensor(BaseModel):
    """Model for Microsoft Defender for Identity sensor.

    Attributes:
        id: The unique identifier for the sensor.
        display_name: The display name of the sensor.
        sensor_type: The type of sensor (domainControllerIntegrated, domainControllerStandalone, adfsIntegrated).
        deployment_status: The deployment status (upToDate, outdated, updating, updateFailed, notConfigured).
        health_status: The health status of the sensor (healthy, notHealthyLow, notHealthyMedium, notHealthyHigh).
        open_health_issues_count: Number of open health issues for this sensor.
        domain_name: The domain name the sensor is monitoring.
        version: The version of the sensor.
        created_date_time: When the sensor was created.
    """

    id: str
    display_name: str
    sensor_type: Optional[str]
    deployment_status: Optional[str]
    health_status: Optional[str]
    open_health_issues_count: int
    domain_name: str
    version: str
    created_date_time: str


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
    issue_type_id: Optional[str]
    recommendations: List[str]
    additional_information: List[str]
