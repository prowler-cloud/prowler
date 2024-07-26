from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################################ Inspector2
class Inspector2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.inspectors = []
        self.__threading_call__(self.__batch_get_account_status__)
        self.__threading_call__(self.__list_active_findings__, self.inspectors)

    def __batch_get_account_status__(self, regional_client):
        # We use this function to check if inspector2 is enabled
        logger.info("Inspector2 - Getting account status...")
        try:
            batch_get_account_status = regional_client.batch_get_account_status(
                accountIds=[self.audited_account]
            )["accounts"][0]
            self.inspectors.append(
                Inspector(
                    id="Inspector2",
                    arn=f"arn:{self.audited_partition}:inspector2:{regional_client.region}:{self.audited_account}:inspector2",
                    status=batch_get_account_status.get("state").get("status"),
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_active_findings__(self, inspector):
        logger.info("Inspector2 - Listing active findings...")
        try:
            regional_client = self.regional_clients[inspector.region]
            active_findings = regional_client.list_findings(
                filterCriteria={
                    "awsAccountId": [
                        {"comparison": "EQUALS", "value": self.audited_account},
                    ],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                },
                maxResults=1,  # Retrieve only 1 finding to check for existence
            )
            inspector.active_findings = len(active_findings.get("findings")) > 0

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Inspector(BaseModel):
    id: str
    arn: str
    region: str
    status: str
    active_findings: bool = False
