from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################### Shield
class Shield(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider, global_service=True)
        self.protections = {}
        self.enabled = False
        self.enabled = self._get_subscription_state()
        if self.enabled:
            self._list_protections()

    def _get_subscription_state(self):
        logger.info("Shield - Getting Subscription State...")
        try:
            return (
                True
                if self.client.get_subscription_state()["SubscriptionState"] == "ACTIVE"
                else False
            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_protections(self):
        logger.info("Shield - Listing Protections...")
        try:
            list_protections_paginator = self.client.get_paginator("list_protections")
            for page in list_protections_paginator.paginate():
                for protection in page["Protections"]:
                    protection_arn = protection.get("ProtectionArn")
                    protection_id = protection.get("Id")
                    protection_name = protection.get("Name")
                    resource_arn = protection.get("ResourceArn")

                    self.protections[protection_id] = Protection(
                        id=protection_id,
                        name=protection_name,
                        resource_arn=resource_arn,
                        protection_arn=protection_arn,
                        region=self.region,
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Protection(BaseModel):
    id: str
    name: str
    resource_arn: str
    protection_arn: str = None
    region: str
