from dataclasses import dataclass

from azure.mgmt.resource.policy import PolicyClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info
from prowler.providers.azure.lib.service.service import AzureService


########################## Policy
class Policy(AzureService):
    def __init__(self, audit_info: Azure_Audit_Info):
        super().__init__(PolicyClient, audit_info)
        self.policy_assigments = self.__get_policy_assigments__()

    def __get_policy_assigments__(self):
        logger.info("Policy - Getting policy assigments...")
        policy_assigments = {}

        for subscription_name, client in self.clients.items():
            try:
                policy_assigments_list = client.policy_assignments.list()
                policy_assigments.update({subscription_name: {}})

                for policy_assigment in policy_assigments_list:
                    policy_assigments[subscription_name].update(
                        {
                            policy_assigment.name: PolicyAssigment(
                                id=policy_assigment.id,
                                enforcement_mode=policy_assigment.enforcement_mode,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return policy_assigments


@dataclass
class PolicyAssigment:
    id: str
    enforcement_mode: str
