from datetime import timedelta

from azure.core.exceptions import HttpResponseError
from azure.mgmt.security import SecurityCenter
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Defender
class Defender(AzureService):
    def __init__(self, audit_info):
        super().__init__(SecurityCenter, audit_info)

        self.pricings = self.__get_pricings__()
        self.auto_provisioning_settings = self.__get_auto_provisioning_settings__()
        self.assessments = self.__get_assessments__()
        self.settings = self.__get_settings__()
        self.security_contacts = self.__get_security_contacts__()
        self.iot_security_solutions = self.__get_iot_security_solutions__()

    def __get_pricings__(self):
        logger.info("Defender - Getting pricings...")
        pricings = {}
        for subscription_name, client in self.clients.items():
            try:
                pricings_list = client.pricings.list()
                pricings.update({subscription_name: {}})
                for pricing in pricings_list.value:
                    pricings[subscription_name].update(
                        {
                            pricing.name: Pricing(
                                resource_id=pricing.id,
                                pricing_tier=pricing.pricing_tier,
                                free_trial_remaining_time=pricing.free_trial_remaining_time,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return pricings

    def __get_auto_provisioning_settings__(self):
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
            except Exception as error:
                logger.error(f"Subscription name: {subscription_name}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return auto_provisioning

    def __get_assessments__(self):
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
                                status=assessment.status.code,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return assessments

    def __get_settings__(self):
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
                                resource_type=setting.type,
                                kind=setting.kind,
                                enabled=setting.enabled,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return settings

    def __get_security_contacts__(self):
        logger.info("Defender - Getting security contacts...")
        security_contacts = {}
        for subscription_name, client in self.clients.items():
            try:
                security_contacts.update({subscription_name: {}})
                # TODO: List all security contacts. For now, the list method is not working.
                security_contact_default = client.security_contacts.get("default")
                security_contacts[subscription_name].update(
                    {
                        security_contact_default.name: SecurityContacts(
                            resource_id=security_contact_default.id,
                            emails=security_contact_default.emails,
                            phone=security_contact_default.phone,
                            alert_notifications_minimal_severity=security_contact_default.alert_notifications.minimal_severity,
                            alert_notifications_state=security_contact_default.alert_notifications.state,
                            notified_roles=security_contact_default.notifications_by_role.roles,
                            notified_roles_state=security_contact_default.notifications_by_role.state,
                        )
                    }
                )
            except HttpResponseError as error:
                if error.status_code == 404:
                    security_contacts[subscription_name].update(
                        {
                            "default": SecurityContacts(
                                resource_id=f"/subscriptions/{self.subscriptions[subscription_name]}/providers/Microsoft.Security/securityContacts/default",
                                emails="",
                                phone="",
                                alert_notifications_minimal_severity="",
                                alert_notifications_state="",
                                notified_roles=[""],
                                notified_roles_state="",
                            )
                        }
                    )
                else:
                    logger.error(
                        f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_contacts

    def __get_iot_security_solutions__(self):
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
                            iot_security_solution.name: IoTSecuritySolution(
                                resource_id=iot_security_solution.id,
                                status=iot_security_solution.status,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return iot_security_solutions


class Pricing(BaseModel):
    resource_id: str
    pricing_tier: str
    free_trial_remaining_time: timedelta


class AutoProvisioningSetting(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    auto_provision: str


class Assesment(BaseModel):
    resource_id: str
    resource_name: str
    status: str


class Setting(BaseModel):
    resource_id: str
    resource_type: str
    kind: str
    enabled: bool


class SecurityContacts(BaseModel):
    resource_id: str
    emails: str
    phone: str
    alert_notifications_minimal_severity: str
    alert_notifications_state: str
    notified_roles: list[str]
    notified_roles_state: str


class IoTSecuritySolution(BaseModel):
    resource_id: str
    status: str
