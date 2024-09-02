from dataclasses import dataclass

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.v2022_04_01.models import Permission

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


########################## IAM
class IAM(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(AuthorizationManagementClient, provider)
        self.roles, self.custom_roles = self._get_roles()
        self.role_assignments = self._get_role_assignments()

    def _get_roles(self):
        logger.info("IAM - Getting roles...")
        builtin_roles = {}
        custom_roles = {}
        for subscription, client in self.clients.items():
            try:
                builtin_roles.update({subscription: []})
                custom_roles.update({subscription: []})
                all_roles = client.role_definitions.list(
                    scope=f"/subscriptions/{self.subscriptions[subscription]}",
                )
                for role in all_roles:
                    if role.role_type == "CustomRole":
                        custom_roles[subscription].append(
                            Role(
                                id=role.id,
                                name=role.role_name,
                                type=role.role_type,
                                assignable_scopes=role.assignable_scopes,
                                permissions=role.permissions,
                            )
                        )
                    else:
                        builtin_roles[subscription].append(
                            Role(
                                id=role.id,
                                name=role.role_name,
                                type=role.role_type,
                                assignable_scopes=role.assignable_scopes,
                                permissions=role.permissions,
                            )
                        )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return builtin_roles, custom_roles

    def _get_role_assignments(self):
        logger.info("IAM - Getting role assignments...")
        role_assignments = {}
        for subscription, client in self.clients.items():
            try:
                role_assignments.update({subscription: {}})
                all_role_assignments = client.role_assignments.list_for_subscription(
                    filter="atScope()"
                )
                for role_assignment in all_role_assignments:
                    role_assignments[subscription].update(
                        {
                            role_assignment.id: RoleAssignment(
                                agent_id=role_assignment.principal_id,
                                agent_type=role_assignment.principal_type,
                                role_id=role_assignment.role_definition_id.split("/")[
                                    -1
                                ],
                            )
                        }
                    )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return role_assignments


@dataclass
class Role:
    id: str
    name: str
    type: str
    assignable_scopes: list[str]
    permissions: list[Permission]


@dataclass
class RoleAssignment:
    agent_id: str
    agent_type: str
    role_id: str
