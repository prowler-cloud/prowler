from asyncio import gather, get_event_loop
from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Users(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)

        loop = get_event_loop()

        # Get users first alone because it is a dependency for other attributes
        self.users = loop.run_until_complete(self._get_users())

        attributes = loop.run_until_complete(
            gather(
                self._get_directory_roles(),
            )
        )

        self.directory_roles = attributes[0]

    async def _get_users(self):
        logger.info("Entra - Getting users...")
        users = {}
        try:
            for tenant, client in self.clients.items():
                users_list = await client.users.get(
                    params={
                        "$select": "id,displayName,userPrincipalName,onPremisesSyncEnabled"
                    }
                )
                users.update({tenant: {}})
                for user in users_list.value:
                    users[tenant].update(
                        {
                            user.user_principal_name: User(
                                id=user.id,
                                name=user.display_name,
                                on_premises_sync_enabled=user.on_premises_sync_enabled,
                            )
                        }
                    )
        except Exception as error:
            if (
                error.__class__.__name__ == "ODataError"
                and error.__dict__.get("response_status_code", None) == 403
            ):
                logger.error(
                    "You need 'UserAuthenticationMethod.Read.All' permission to access this information. It only can be granted through Service Principal authentication."
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return users

    async def _get_directory_roles(self):
        logger.info("Entra - Getting directory roles...")
        directory_roles_with_members = {}
        try:
            for tenant, client in self.clients.items():
                directory_roles_with_members.update({tenant: {}})
                directory_roles = await client.directory_roles.get()
                for directory_role in directory_roles.value:
                    directory_role_members = (
                        await client.directory_roles.by_directory_role_id(
                            directory_role.id
                        ).members.get()
                    )
                    directory_roles_with_members[tenant].update(
                        {
                            directory_role.display_name: DirectoryRole(
                                id=directory_role.id,
                                members=[
                                    self.users[tenant][member.user_principal_name]
                                    for member in directory_role_members.value
                                    if self.users[tenant].get(
                                        member.user_principal_name, None
                                    )
                                ],
                            )
                        }
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return directory_roles_with_members


class User(BaseModel):
    id: str
    name: str
    on_premises_sync_enabled: Optional[bool] = None


class DirectoryRole(BaseModel):
    id: str
    members: List[User]
