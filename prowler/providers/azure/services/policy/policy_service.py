from dataclasses import dataclass

from azure.mgmt.resource.policy import PolicyClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Policy(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(PolicyClient, provider)
        self.policy_assigments = self._get_policy_assigments()

    def _get_policy_assigments(self):
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
                                name=policy_assigment.name,
                                enforcement_mode=policy_assigment.enforcement_mode,
                            )
                        }
                    )
            except Exception as error:
                logger.exception(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return policy_assigments


@dataclass
class PolicyAssigment:
    id: str
    name: str
    enforcement_mode: str
