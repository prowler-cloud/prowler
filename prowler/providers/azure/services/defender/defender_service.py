from datetime import timedelta

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
        self.security_contacts = self.__get_security_contacts__()

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
                            pricing.name: Defender_Pricing(
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
                            assessment.display_name: Defender_Assessments(
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

    def __get_security_contacts__(self):
        logger.info("Defender - Getting security contacts...")
        security_contacts = {}
        for subscription_name, client in self.clients.items():
            try:
                # TODO: List all security contacts. For now, the list method is not working.
                security_contact_default = client.security_contacts.get("default")
                security_contacts.update({subscription_name: {}})
                security_contacts[subscription_name].update(
                    {
                        security_contact_default.name: Defender_Security_Contacts(
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
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_contacts


class Defender_Pricing(BaseModel):
    resource_id: str
    pricing_tier: str
    free_trial_remaining_time: timedelta


class AutoProvisioningSetting(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    auto_provision: str


class Defender_Assessments(BaseModel):
    resource_id: str
    resource_name: str
    status: str


class Defender_Security_Contacts(BaseModel):
    resource_id: str
    emails: str
    phone: str
    alert_notifications_minimal_severity: str
    alert_notifications_state: str
    notified_roles: list[str]
    notified_roles_state: str
