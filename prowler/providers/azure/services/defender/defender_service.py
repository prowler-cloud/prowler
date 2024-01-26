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

    def __get_pricings__(self):
        logger.info("Defender - Getting pricings...")
        pricings = {}
        for subscription, client in self.clients.items():
            try:
                pricings_list = client.pricings.list()
                pricings.update({subscription: {}})
                for pricing in pricings_list.value:
                    pricings[subscription].update(
                        {
                            pricing.name: Defender_Pricing(
                                resource_id=pricing.id,
                                pricing_tier=pricing.pricing_tier,
                                free_trial_remaining_time=pricing.free_trial_remaining_time,
                            )
                        }
                    )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return pricings
    
    def __get_auto_provisioning_settings__(self):
        logger.info("Defender - Getting auto provisioning settings...")
        auto_provisioning = {}
        for subscription, client in self.clients.items():
            try:
                auto_provisioning_settings = client.auto_provisioning_settings.list()
                auto_provisioning.update({subscription: {}})
                for ap in auto_provisioning_settings:
                    auto_provisioning[subscription].update(
                        {
                            ap.name: AutoProvisioningSetting(
                                resource_id=ap.id,
                                resource_type=ap.type,
                                auto_provision=ap.auto_provision,
                            )
                        }
                    )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return auto_provisioning


class Defender_Pricing(BaseModel):
    resource_id: str
    pricing_tier: str
    free_trial_remaining_time: timedelta

class AutoProvisioningSetting(BaseModel):
    resource_id: str
    resource_type: str
    auto_provision: str
