import asyncio
from dataclasses import dataclass
from typing import Optional

from msgraph import GraphServiceClient
from msgraph.generated.models.default_user_role_permissions import (
    DefaultUserRolePermissions,
)
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Entra
class Entra(AzureService):
    def __init__(self, azure_audit_info):
        super().__init__(GraphServiceClient, azure_audit_info)
        self.users = asyncio.get_event_loop().run_until_complete(self.__get_users__())
        self.authorization_policy = asyncio.get_event_loop().run_until_complete(
            self.__get_authorization_policy__()
        )

    async def __get_users__(self):
        try:
            users = {}
            for client in self.clients.values():
                users_list = await client.users.get()
                for user in users_list.value:
                    users.update(
                        {
                            user.user_principal_name: User(
                                id=user.id, name=user.display_name
                            )
                        }
                    )
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users

    async def __get_authorization_policy__(self):
        try:
            authorization_policy = None
            for client in self.clients.values():
                auth_policy = await client.policies.authorization_policy.get()
                authorization_policy = AuthorizationPolicy(
                    id=auth_policy.id,
                    name=auth_policy.display_name,
                    description=auth_policy.description,
                    default_user_role_permissions=getattr(
                        auth_policy, "default_user_role_permissions", None
                    ),
                )
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return authorization_policy


class User(BaseModel):
    id: str
    name: str


@dataclass
class AuthorizationPolicy:
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions]
