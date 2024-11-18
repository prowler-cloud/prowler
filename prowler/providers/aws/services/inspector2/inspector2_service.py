from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################################ Inspector2
class Inspector2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.inspectors = []
        self.__threading_call__(self._batch_get_account_status)
        self.__threading_call__(self._list_active_findings, self.inspectors)

    def _batch_get_account_status(self, regional_client):
        # We use this function to check if inspector2 is enabled
        logger.info("Inspector2 - Getting account status...")
        try:
            batch_get_account_status = regional_client.batch_get_account_status(
                accountIds=[self.audited_account]
            )["accounts"][0]
            resourceStates = batch_get_account_status.get("resourceState")
            self.inspectors.append(
                Inspector(
                    id="Inspector2",
                    arn=f"arn:{self.audited_partition}:inspector2:{regional_client.region}:{self.audited_account}:inspector2",
                    status=batch_get_account_status.get("state").get("status"),
                    ec2_status=resourceStates.get("ec2", {}).get("status"),
                    ecr_status=resourceStates.get("ecr", {}).get("status"),
                    lambda_status=resourceStates.get("lambda", {}).get("status"),
                    lambda_code_status=resourceStates.get("lambdaCode", {}).get(
                        "status"
                    ),
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_active_findings(self, inspector):
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
    ec2_status: str
    ecr_status: str
    lambda_status: str
    lambda_code_status: str
    active_findings: bool = False
