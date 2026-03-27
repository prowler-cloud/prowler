import asyncio
from typing import Optional

from kiota_abstractions.base_request_configuration import RequestConfiguration
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Intune(M365Service):
    """Microsoft Intune service class."""

    MDM_MANAGEMENT_AGENTS = {
        "mdm",
        "easMdm",
        "intuneClient",
        "easIntuneClient",
        "configurationManagerClientMdm",
        "configurationManagerClientMdmEas",
        "microsoft365ManagedMdm",
    }

    def __init__(self, provider: M365Provider):
        super().__init__(provider)

        self.tenant_domain = provider.identity.tenant_domain
        self.settings: Optional[IntuneSettings] = None
        self.compliance_policies: Optional[list[IntuneCompliancePolicy]] = []
        self.managed_devices: Optional[list[IntuneManagedDevice]] = []
        self.verification_error: Optional[str] = None

        loop = self._get_event_loop()
        try:
            (
                settings,
                settings_error,
                policies,
                policies_error,
                managed_devices,
                managed_devices_error,
            ) = loop.run_until_complete(self._load_intune_configuration())
            self.settings = settings
            self.compliance_policies = policies
            self.managed_devices = managed_devices
            self.verification_error = (
                " ".join(
                    error
                    for error in [
                        settings_error,
                        policies_error,
                        managed_devices_error,
                    ]
                    if error
                )
                or None
            )
        finally:
            self._cleanup_event_loop(loop)

    def _get_event_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create an event loop for async operations."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                raise RuntimeError(
                    "Cannot initialize Intune service while event loop is running"
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
        except Exception as error:
            logger.debug(f"Intune - Failed to clean up event loop: {error}")

    async def _load_intune_configuration(
        self,
    ) -> tuple[
        Optional["IntuneSettings"],
        Optional[str],
        Optional[list["IntuneCompliancePolicy"]],
        Optional[str],
        Optional[list["IntuneManagedDevice"]],
        Optional[str],
    ]:
        settings, settings_error = await self._get_settings()
        policies, policies_error = await self._get_compliance_policies()
        managed_devices, managed_devices_error = await self._get_managed_devices()
        return (
            settings,
            settings_error,
            policies,
            policies_error,
            managed_devices,
            managed_devices_error,
        )

    async def _get_settings(self) -> tuple[Optional["IntuneSettings"], Optional[str]]:
        """Retrieve Intune tenant settings required for compliance evaluation."""
        logger.info("Intune - Getting device management settings...")

        try:
            from msgraph.generated.device_management.device_management_request_builder import (
                DeviceManagementRequestBuilder,
            )

            query_parameters = (
                DeviceManagementRequestBuilder.DeviceManagementRequestBuilderGetQueryParameters()
            )
            query_parameters.select = ["settings"]
            request_configuration = RequestConfiguration(
                query_parameters=query_parameters
            )

            device_management = await self.client.device_management.get(
                request_configuration=request_configuration
            )
            settings = getattr(device_management, "settings", None)
            if settings is None:
                return (
                    IntuneSettings(secure_by_default=None),
                    None,
                )

            return (
                IntuneSettings(
                    secure_by_default=getattr(settings, "secure_by_default", None)
                ),
                None,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return (
                None,
                "Could not read Microsoft Intune device management settings. Ensure the Service Principal has DeviceManagementServiceConfig.Read.All permission granted.",
            )

    async def _get_compliance_policies(
        self,
    ) -> tuple[Optional[list["IntuneCompliancePolicy"]], Optional[str]]:
        """Retrieve Intune device compliance policies and their assignments."""
        logger.info("Intune - Getting device compliance policies...")
        policies: list[IntuneCompliancePolicy] = []

        try:
            response = (
                await self.client.device_management.device_compliance_policies.get()
            )

            while response:
                for policy in getattr(response, "value", []) or []:
                    assignment_count, assignment_error = (
                        await self._get_assignment_count(getattr(policy, "id", ""))
                    )
                    if assignment_error:
                        return None, assignment_error

                    policies.append(
                        IntuneCompliancePolicy(
                            id=getattr(policy, "id", ""),
                            display_name=getattr(policy, "display_name", ""),
                            assignment_count=assignment_count,
                        )
                    )

                next_link = getattr(response, "odata_next_link", None)
                if not next_link:
                    break
                response = await self.client.device_management.device_compliance_policies.with_url(
                    next_link
                ).get()

            return policies, None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return (
                None,
                "Could not read Microsoft Intune device compliance policies. Ensure the Service Principal has DeviceManagementConfiguration.Read.All permission granted.",
            )

    async def _get_assignment_count(self, policy_id: str) -> tuple[int, Optional[str]]:
        """Count assignments for a single Intune device compliance policy."""
        if not policy_id:
            return 0, None

        try:
            assignments_response = await self.client.device_management.device_compliance_policies.by_device_compliance_policy_id(
                policy_id
            ).assignments.get()

            assignment_count = 0
            while assignments_response:
                assignment_count += len(
                    getattr(assignments_response, "value", []) or []
                )
                next_link = getattr(assignments_response, "odata_next_link", None)
                if not next_link:
                    break
                assignments_response = (
                    await self.client.device_management.device_compliance_policies.by_device_compliance_policy_id(
                        policy_id
                    )
                    .assignments.with_url(next_link)
                    .get()
                )

            return assignment_count, None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return (
                0,
                "Could not read Microsoft Intune device compliance policy assignments. Ensure the Service Principal has DeviceManagementConfiguration.Read.All permission granted.",
            )

    async def _get_managed_devices(
        self,
    ) -> tuple[Optional[list["IntuneManagedDevice"]], Optional[str]]:
        """Retrieve Intune managed devices needed for operational evidence."""
        logger.info("Intune - Getting managed devices...")
        managed_devices: list[IntuneManagedDevice] = []

        try:
            from msgraph.generated.device_management.managed_devices.managed_devices_request_builder import (
                ManagedDevicesRequestBuilder,
            )

            query_parameters = (
                ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters()
            )
            query_parameters.select = [
                "id",
                "deviceName",
                "complianceState",
                "managementAgent",
            ]
            request_configuration = RequestConfiguration(
                query_parameters=query_parameters
            )

            response = await self.client.device_management.managed_devices.get(
                request_configuration=request_configuration
            )

            while response:
                for device in getattr(response, "value", []) or []:
                    managed_devices.append(
                        IntuneManagedDevice(
                            id=getattr(device, "id", ""),
                            device_name=getattr(device, "device_name", ""),
                            compliance_state=(
                                str(getattr(device, "compliance_state", ""))
                                if getattr(device, "compliance_state", None)
                                else ""
                            ),
                            management_agent=(
                                str(getattr(device, "management_agent", ""))
                                if getattr(device, "management_agent", None)
                                else ""
                            ),
                        )
                    )

                next_link = getattr(response, "odata_next_link", None)
                if not next_link:
                    break
                response = await self.client.device_management.managed_devices.with_url(
                    next_link
                ).get()

            return managed_devices, None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return (
                None,
                "Could not read Microsoft Intune managed devices. Ensure the Service Principal has DeviceManagementManagedDevices.Read.All permission granted.",
            )

    @classmethod
    def is_mdm_managed_device(cls, management_agent: str) -> bool:
        """Return whether a management agent represents MDM or Intune management."""
        return management_agent in cls.MDM_MANAGEMENT_AGENTS


class IntuneSettings(BaseModel):
    secure_by_default: Optional[bool] = None


class IntuneCompliancePolicy(BaseModel):
    id: str
    display_name: str
    assignment_count: int = 0


class IntuneManagedDevice(BaseModel):
    id: str
    device_name: str = ""
    compliance_state: str = ""
    management_agent: str = ""
