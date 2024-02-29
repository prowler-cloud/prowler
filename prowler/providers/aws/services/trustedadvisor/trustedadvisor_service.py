from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################################ TrustedAdvisor
class TrustedAdvisor(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("support", provider)
        self.checks = []
        self.premium_support = PremiumSupport(enabled=False)
        # Support API is not available in China Partition
        # But only in us-east-1 or us-gov-west-1 https://docs.aws.amazon.com/general/latest/gr/awssupport.html
        if provider.audited_partition != "aws-cn":
            if provider.audited_partition == "aws":
                support_region = "us-east-1"
            else:
                support_region = "us-gov-west-1"

            self.client = provider.audit_session.client(
                self.service, region_name=support_region
            )
            self.client.region = support_region
            self.__describe_services__()
            if self.premium_support.enabled:
                self.__describe_trusted_advisor_checks__()
                self.__describe_trusted_advisor_check_result__()

    def __describe_trusted_advisor_checks__(self):
        logger.info("TrustedAdvisor - Describing Checks...")
        try:
            for check in self.client.describe_trusted_advisor_checks(language="en").get(
                "checks", []
            ):
                self.checks.append(
                    Check(
                        id=check["id"],
                        name=check["name"],
                        region=self.client.region,
                    )
                )
        except ClientError as error:
            if (
                error.response["Error"]["Code"] == "SubscriptionRequiredException"
                and error.response["Error"]["Message"]
                == "Amazon Web Services Premium Support Subscription is required to use this service."
            ):
                logger.warning(
                    f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
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

    def __describe_services__(self):
        logger.info("Support - Describing Services...")
        try:
            self.client.describe_services()
            # If the above call succeeds the account has a Business,
            # Enterprise On-Ramp, or Enterprise Support plan.
            self.premium_support.enabled = True

        except ClientError as error:
            if (
                error.response["Error"]["Code"] == "SubscriptionRequiredException"
                and error.response["Error"]["Message"]
                == "Amazon Web Services Premium Support Subscription is required to use this service."
            ):
                logger.warning(
                    f"{self.region} --"
                    f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                    f" {error}"
                )

        except Exception as error:
            logger.error(
                f"{self.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class Check(BaseModel):
    id: str
    name: str
    status: Optional[str]
    region: str


class PremiumSupport(BaseModel):
    enabled: bool
