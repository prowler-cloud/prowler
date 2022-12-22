from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ TrustedAdvisor
class TrustedAdvisor:
    def __init__(self, audit_info):
        self.service = "support"
        self.session = audit_info.audit_session
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.checks = []
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.__describe_trusted_advisor_checks__()
            self.__describe_trusted_advisor_check_result__()

    def __get_session__(self):
        return self.session

    def __describe_trusted_advisor_checks__(self):
        logger.info("TrustedAdvisor - Describing Checks...")
        try:
            for check in self.client.describe_trusted_advisor_checks(language="en")[
                "checks"
            ]:
                self.checks.append(
                    Check(
                        id=check["id"],
                        name=check["name"],
                        region=self.client.region,
                    )
                )
        except ClientError as error:
            if error.response["Error"]["Code"] != "SubscriptionRequiredException":
                logger.error(
                    f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_trusted_advisor_check_result__(self):
        logger.info("TrustedAdvisor - Describing Check Result...")
        try:
            for check in self.checks:
                if check.region == self.client.region:
                    response = self.client.describe_trusted_advisor_check_result(
                        checkId=check.id
                    )
                    if "result" in response:
                        check.status = response["result"]["status"]
        except Exception as error:
            logger.error(
                f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Check(BaseModel):
    id: str
    name: str
    status: Optional[str]
    region: str
