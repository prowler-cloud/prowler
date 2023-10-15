from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## Data Lifecycle Manager
class DLM(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.lifecycle_policies = {}
        self.__threading_call__(self.__get_lifecycle_policies__)

    def __get_lifecycle_policies__(self, regional_client):
        logger.info("DLM - Getting EBS Snapshots Lifecycle Policies...")
        try:
            lifecycle_policies = regional_client.get_lifecycle_policies()
            self.lifecycle_policies[regional_client.region] = lifecycle_policies[
                "Policies"
            ]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
