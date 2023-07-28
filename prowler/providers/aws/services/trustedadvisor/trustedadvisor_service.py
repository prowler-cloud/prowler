from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWS_Service


################################ TrustedAdvisor
class TrustedAdvisor(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__("support", audit_info)
        self.checks = []
        self.enabled = True
        # Support API is not available in China Partition
        # But only in us-east-1 or us-gov-west-1 https://docs.aws.amazon.com/general/latest/gr/awssupport.html
        if audit_info.audited_partition != "aws-cn":
            if audit_info.audited_partition == "aws":
                support_region = "us-east-1"
            else:
                support_region = "us-gov-west-1"

            self.client = audit_info.audit_session.client(
                self.service, region_name=support_region
            )
            self.client.region = support_region
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
            if error.response["Error"]["Code"] == "SubscriptionRequiredException":
                self.enabled = False
            else:
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
                    try:
                        response = self.client.describe_trusted_advisor_check_result(
                            checkId=check.id
                        )
                        if "result" in response:
                            check.status = response["result"]["status"]
                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "InvalidParameterValueException"
                        ):
                            logger.warning(
                                f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
        except Exception as error:
            logger.error(
                f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Check(BaseModel):
    id: str
    name: str
    status: Optional[str]
    region: str
