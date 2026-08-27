"""
This module contains the Policy service class and models for Azure Policy.
"""

from dataclasses import dataclass
from typing import Optional

from azure.mgmt.resource.policy import PolicyClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Policy(AzureService):
    """Policy service class for Azure."""

    def __init__(self, provider: AzureProvider):
        """Initialize the Policy service."""
        super().__init__(PolicyClient, provider)
        self.policy_assigments = self._get_policy_assigments()

    def _get_policy_assigments(self):
        """Get policy assignments for all subscriptions."""
        logger.info("Policy - Getting policy assigments...")
        policy_assigments = {}

        for subscription_id, client in self.clients.items():
            try:
                policy_assigments.update({subscription_id: {}})
                policy_assigments_list = client.policy_assignments.list()

                for policy_assigment in policy_assigments_list:
                    policy_assigments[subscription_id].update(
                        {
                            policy_assigment.name: PolicyAssigment(
                                id=policy_assigment.id,
                                name=policy_assigment.name,
                                enforcement_mode=policy_assigment.enforcement_mode,
                                parameters=getattr(
                                    policy_assigment, "parameters", None
                                ),
                                policy_definition_id=getattr(
                                    policy_assigment, "policy_definition_id", None
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return policy_assigments


@dataclass
class PolicyAssigment:
    """PolicyAssigment data model."""

    id: str
    name: str
    enforcement_mode: str
    parameters: Optional[dict] = None
    policy_definition_id: Optional[str] = None


def check_policy_assignment_exists(
    assignments: dict[str, PolicyAssigment], definition_id: str
) -> bool:
    """
    Check if a specific policy definition is assigned and enforced.

    Args:
        assignments (dict[str, PolicyAssigment]): Dictionary of policy assignments.
        definition_id (str): The policy definition ID to check.

    Returns:
        bool: True if the policy is assigned and enforced (Default mode), False otherwise.
    """
    for assignment in assignments.values():
        if (
            assignment.policy_definition_id
            and definition_id.lower() in assignment.policy_definition_id.lower()
            and assignment.enforcement_mode == "Default"
        ):
            return True
    return False
