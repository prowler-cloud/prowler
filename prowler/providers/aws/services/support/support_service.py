from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## Support
class Support(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.support_services = []
        self.__threading_call__(self.__describe_services__)
        print(self.support_services)

    def __describe_services__(self, regional_client):
        logger.info("Support - Describing Services...")
        try:
            try:
                regional_client.describe_services()
                self.support_services.append(
                    SupportServices(region=regional_client.region, premium_support=True)
                )
            except ClientError as error:
                if (
                    error.response.get("Error", {}).get("Code")
                    == "SubscriptionRequiredException"
                ):
                    self.support_services.append(
                        SupportServices(
                            region=regional_client.region, premium_support=False
                        )
                    )
                else:
                    raise error
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class SupportServices(BaseModel):
    region: str
    premium_support: bool
