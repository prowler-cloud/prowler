from datetime import timedelta
from typing import Dict, Optional

import requests
from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
from azure.mgmt.security import SecurityCenter
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Defender(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(SecurityCenter, provider)

        self.pricings = self._get_pricings()
        self.auto_provisioning_settings = self._get_auto_provisioning_settings()
        self.assessments = self._get_assessments()
        self.settings = self._get_settings()
        self.security_contact_configurations = self._get_security_contacts(
            token=provider.session.get_token(
                "https://management.azure.com/.default"
            ).token
        )
        self.iot_security_solutions = self._get_iot_security_solutions()
        self.jit_policies = self._get_jit_policies()

    def _get_pricings(self):
        logger.info("Defender - Getting pricings...")
        pricings = {}
        for subscription_name, client in self.clients.items():
            try:
                pricings_list = client.pricings.list(
                    scope_id=f"subscriptions/{self.subscriptions[subscription_name]}"
                )
                pricings.update({subscription_name: {}})
                for pricing in pricings_list.value:
                    pricings[subscription_name].update(
                        {
                            pricing.name: Pricing(
                                resource_id=pricing.id,
                                resource_name=pricing.name,
                                pricing_tier=getattr(pricing, "pricing_tier", None),
                                free_trial_remaining_time=pricing.free_trial_remaining_time,
                                extensions=dict(
                                    [
                                        (extension.name, extension.is_enabled)
                                        for extension in (
                                            pricing.extensions
                                            if getattr(pricing, "extensions", None)
                                            else []
                                        )
                                    ]
                                ),
                            )
                        }
                    )
            except ResourceNotFoundError as error:
                if "Subscription Not Registered" in error.message:
                    logger.error(
                        f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: Subscription Not Registered - Please register to Microsoft.Security in order to view your security status"
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return pricings

    def _get_auto_provisioning_settings(self):
        logger.info("Defender - Getting auto provisioning settings...")
        auto_provisioning = {}
        for subscription_name, client in self.clients.items():
            try:
                auto_provisioning_settings = client.auto_provisioning_settings.list()
                auto_provisioning.update({subscription_name: {}})
                for ap in auto_provisioning_settings:
                    auto_provisioning[subscription_name].update(
                        {
                            ap.name: AutoProvisioningSetting(
                                resource_id=ap.id,
                                resource_name=ap.name,
                                resource_type=ap.type,
                                auto_provision=ap.auto_provision,
                            )
                        }
                    )
            except ClientAuthenticationError as error:
                if "Subscription Not Registered" in error.message:
                    logger.error(
                        f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: Subscription Not Registered - Please register to Microsoft.Security in order to view your security status"
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return auto_provisioning

    def _get_assessments(self):
        logger.info("Defender - Getting assessments...")
        assessments = {}
        for subscription_name, client in self.clients.items():
            try:
                assessments_list = client.assessments.list(
                    f"subscriptions/{self.subscriptions[subscription_name]}"
                )
                assessments.update({subscription_name: {}})
                for assessment in assessments_list:
                    assessments[subscription_name].update(
                        {
                            assessment.display_name: Assesment(
                                resource_id=assessment.id,
                                resource_name=assessment.name,
                                status=getattr(
                                    getattr(assessment, "status", None), "code", None
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return assessments

    def _get_settings(self):
        logger.info("Defender - Getting settings...")
        settings = {}
        for subscription_name, client in self.clients.items():
            try:
                settings_list = client.settings.list()
                settings.update({subscription_name: {}})
                for setting in settings_list:
                    settings[subscription_name].update(
                        {
                            setting.name: Setting(
                                resource_id=setting.id,
                                resource_name=setting.name or setting.id,
                                resource_type=setting.type,
                                kind=setting.kind,
                                enabled=setting.enabled,
                            )
                        }
                    )
            except ClientAuthenticationError as error:
                if "Subscription Not Registered" in error.message:
                    logger.error(
                        f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: Subscription Not Registered - Please register to Microsoft.Security in order to view your security status"
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return settings

    def _get_security_contacts(self, token: str) -> dict[str, dict]:
        """
        Get all security contacts configuration for all subscriptions.

        Args:
            token: The authentication token to make the request.

        Returns:
            A dictionary of security contacts for all subscriptions.
        """
        logger.info("Defender - Getting security contacts...")
        security_contacts = {}
        for subscription_name, subscription_id in self.subscriptions.items():
            try:
                url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                contact_configurations = response.json().get("value", [])
                security_contacts[subscription_name] = {}
                for contact_configuration in contact_configurations:
                    props = contact_configuration.get("properties", {})

                    # Map notificationsByRole.state from "On"/"Off" to boolean
                    notifications_by_role_state = props.get(
                        "notificationsByRole", {}
                    ).get("state", "Off")
                    notifications_by_role_state_bool = (
                        notifications_by_role_state.lower() == "on"
                    )
                    notifications_by_role_roles = props.get(
                        "notificationsByRole", {}
                    ).get("roles", [])

                    # Extract minimalRiskLevel and minimalSeverity from notificationsSources
                    attack_path_minimal_risk_level = None
                    alert_minimal_severity = None
                    for source in props.get("notificationsSources", []):
                        if source.get("sourceType") == "AttackPath":
                            value = source.get("minimalRiskLevel")
                            if value is not None:
                                attack_path_minimal_risk_level = value
                        elif source.get("sourceType") == "Alert":
                            value = source.get("minimalSeverity")
                            if value is not None:
                                alert_minimal_severity = value

                    security_contacts[subscription_name][
                        contact_configuration.get("name", "default")
                    ] = SecurityContactConfiguration(
                        id=contact_configuration.get("id", ""),
                        name=contact_configuration.get("name", "default"),
                        enabled=props.get("isEnabled", False),
                        emails=props.get("emails", "").split(";"),
                        phone=props.get("phone", ""),
                        notifications_by_role=NotificationsByRole(
                            state=notifications_by_role_state_bool,
                            roles=notifications_by_role_roles,
                        ),
                        attack_path_minimal_risk_level=attack_path_minimal_risk_level,
                        alert_minimal_severity=alert_minimal_severity,
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_contacts

    def _get_iot_security_solutions(self):
        logger.info("Defender - Getting IoT Security Solutions...")
        iot_security_solutions = {}
        for subscription_name, client in self.clients.items():
            try:
                iot_security_solutions_list = (
                    client.iot_security_solution.list_by_subscription()
                )
                iot_security_solutions.update({subscription_name: {}})
                for iot_security_solution in iot_security_solutions_list:
                    iot_security_solutions[subscription_name].update(
                        {
                            iot_security_solution.id: IoTSecuritySolution(
                                resource_id=iot_security_solution.id,
                                name=iot_security_solution.name,
                                status=iot_security_solution.status,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return iot_security_solutions

    def _get_jit_policies(self) -> dict[str, dict]:
        """
        Get all JIT policies for all subscriptions.

        Returns:
            A dictionary of JIT policies for each subscription. The format will be:
            {
                "subscription_name": {
                    "jit_policy_id": JITPolicy
                }
            }
        """
        logger.info("Defender - Getting JIT policies...")
        jit_policies = {}
        for subscription_name, client in self.clients.items():
            try:
                jit_policies[subscription_name] = {}
                policies = client.jit_network_access_policies.list()
                for policy in policies:
                    vm_ids = set()
                    for vm in getattr(policy, "virtual_machines", []):
                        vm_ids.add(vm.id)
                    jit_policies[subscription_name].update(
                        {
                            policy.id: JITPolicy(
                                id=policy.id,
                                name=policy.name,
                                location=getattr(policy, "location", "Global"),
                                vm_ids=vm_ids,
                            ),
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return jit_policies


class Pricing(BaseModel):
    resource_id: str
    resource_name: str
    pricing_tier: str
    free_trial_remaining_time: timedelta
    extensions: Dict[str, bool] = {}


class AutoProvisioningSetting(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    auto_provision: str


class Assesment(BaseModel):
    resource_id: str
    resource_name: str
    status: Optional[str] = None


class Setting(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    kind: str
    enabled: bool


class NotificationsByRole(BaseModel):
    """
    Defines whether to send email notifications from Microsoft Defender for Cloud to persons with specific RBAC roles on the subscription.

    Attributes:
        state: Whether notifications by role are enabled.
        roles: List of Azure roles (e.g., 'Owner', 'Admin') to be notified.
    """

    state: bool
    roles: list[str]


class SecurityContactConfiguration(BaseModel):
    """
    Represents the configuration of an Azure Security Center security contact.

    Attributes:
        id: The unique resource ID of the security contact.
        name: The name of the security contact (usually 'default').
        enabled: Whether the security contact is enabled. If enabled, the security contact will receive notifications, otherwise it will not.
        emails: List of email addresses to notify.
        phone: Contact phone number.
        notifications_by_role: Defines whether to send email notifications from Microsoft Defender for Cloud to persons with specific RBAC roles on the subscription.
        attack_path_minimal_risk_level: Minimal risk level for Attack Path notifications (e.g., 'Critical').
        alert_minimal_severity: Minimal severity for Alert notifications (e.g., 'Medium').
    """

    id: str
    name: str
    enabled: bool
    emails: list[str]
    phone: Optional[str] = None
    notifications_by_role: NotificationsByRole
    attack_path_minimal_risk_level: Optional[str] = None
    alert_minimal_severity: Optional[str] = None


class IoTSecuritySolution(BaseModel):
    resource_id: str
    name: str
    status: str


class JITPolicy(BaseModel):
    id: str
    name: str
    location: str = ""
    vm_ids: list[str] = []
