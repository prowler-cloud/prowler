from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################### Shield
class Shield:
    def __init__(self, audit_info):
        self.service = "shield"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.protections = {}
        self.enabled = False
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.enabled = self.__get_subscription_state__()
            if self.enabled:
                self.__list_protections__()

    def __get_session__(self):
        return self.session

    def __get_subscription_state__(self):
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

    def __list_protections__(self):
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
