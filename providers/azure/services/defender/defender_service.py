from datetime import timedelta

from azure.mgmt.security import SecurityCenter
from pydantic import BaseModel


########################## Defender
class Defender:
    def __init__(self, audit_info):
        self.service = "defender"
        self.credentials = audit_info.credentials
        self.subscriptions = audit_info.subscriptions
        self.clients = self.__set_clients__(
            audit_info.subscriptions, audit_info.credentials
        )
        self.pricings = self.__get_pricings__()
        self.region = "azure"

    def __set_clients__(self, subscriptions, credentials):
        clients = {}
        for subscription in subscriptions:
            clients.update(
                {
                    subscription.id: SecurityCenter(
                        credential=credentials, subscription_id=subscription.id
                    )
                }
            )
        return clients

    def __get_pricings__(self):
        pricings = {}
        for subscription, client in self.clients.items():
            pricings_list = client.pricings.list()
            for pricing in pricings_list.value:
                pricings.update(
                    {
                        pricing.name: Defender_Pricing(
                            subscription=subscription,
                            name=pricing.name,
                            pricing_tier=pricing.pricing_tier,
                            free_trial_remaining_time=pricing.free_trial_remaining_time,
                        )
                    }
                )
        return pricings


class Defender_Pricing(BaseModel):
    subscription: str
    name: str
    pricing_tier: str
    free_trial_remaining_time: timedelta
