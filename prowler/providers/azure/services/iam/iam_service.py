from dataclasses import dataclass

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.v2022_04_01.models import Permission

from prowler.lib.logger import logger


########################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.credentials = audit_info.credentials
        self.subscriptions = audit_info.identity.subscriptions
        self.clients = self.__set_clients__(
            audit_info.identity.subscriptions, audit_info.credentials
        )
        self.roles = self.__get_roles__()
        self.region = "azure"

    def __set_clients__(self, subscriptions, credentials):
        clients = {}
        try:
            for display_name, id in subscriptions.items():
                clients.update(
                    {
                        display_name: AuthorizationManagementClient(
                            credential=credentials, subscription_id=id
                        )
                    }
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return clients

    def __get_roles__(self):
        logger.info("IAM - Getting roles...")
        roles = {}
        try:
            for subscription, client in self.clients.items():
                roles.update({subscription: []})
                for role in client.role_definitions.list(
                    scope=f"/subscriptions/{self.subscriptions[subscription]}",
                    filter="type eq 'CustomRole'",
                ):
                    roles[subscription].append(
                        Role(
                            id=role.id,
                            name=role.role_name,
                            type=role.role_type,
                            assignable_scopes=role.assignable_scopes,
                            permissions=role.permissions,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return roles


@dataclass
class Role:
    id: str
    name: str
    type: str
    assignable_scopes: list[str]
    permissions: list[Permission]

    def __init__(self, id, name, type, assignable_scopes, permissions):
        self.id = id
        self.name = name
        self.type = type
        self.assignable_scopes = assignable_scopes
        self.permissions = permissions
