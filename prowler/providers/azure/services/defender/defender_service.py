from datetime import timedelta

from azure.mgmt.security import SecurityCenter
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Defender
class Defender(AzureService):
    def __init__(self, provider):
        super().__init__(SecurityCenter, provider)

        self.pricings = self.__get_pricings__()

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


class Defender_Pricing(BaseModel):
    resource_id: str
    pricing_tier: str
    free_trial_remaining_time: timedelta
