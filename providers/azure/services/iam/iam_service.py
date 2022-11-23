from dataclasses import dataclass

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.v2022_04_01.models import Permission


########################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.credentials = audit_info.credentials
        self.subscriptions = audit_info.subscriptions
        self.clients = self.__set_clients__(
            audit_info.subscriptions, audit_info.credentials
        )
        self.roles = self.__get_roles__()
        self.region = "azure"

    def __set_clients__(self, subscriptions, credentials):
        clients = {}
        for subscription in subscriptions:
            clients.update(
                {
                    subscription.id: AuthorizationManagementClient(
                        credential=credentials, subscription_id=subscription.id
                    )
                }
            )
        return clients

    def __get_roles__(self):
        roles = []
        for subscription, client in self.clients.items():
            for role in client.role_definitions.list(
                scope=f"/subscriptions/{subscription}", filter="type eq 'CustomRole'"
            ):
                roles.append(
                    Role(
                        id=role.name,
                        name=role.role_name,
                        type=role.role_type,
                        assignable_scopes=role.assignable_scopes,
                        permissions=role.permissions,
                        role_subscription=subscription,
                    )
                )

        return roles


@dataclass
class Role:
    id: str
    name: str
    type: str
    assignable_scopes: list[str]
    permissions: list[Permission]
    role_subscription: str

    def __init__(
        self, id, name, type, assignable_scopes, permissions, role_subscription
    ):
        self.id = id
        self.name = name
        self.type = type
        self.assignable_scopes = assignable_scopes
        self.permissions = permissions
        self.role_subscription = role_subscription
