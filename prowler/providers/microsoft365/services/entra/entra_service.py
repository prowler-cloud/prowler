from asyncio import gather, get_event_loop
from typing import Optional

from msgraph.generated.models.default_user_role_permissions import (
    DefaultUserRolePermissions,
)
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Entra(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)

        loop = get_event_loop()

        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
            )
        )

        self.authorization_policy = attributes[0]

    async def _get_authorization_policy(self):
        logger.info("Entra - Getting authorization policy...")

        authorization_policy = {}
        try:
            auth_policy = await self.client.policies.authorization_policy.get()
            authorization_policy.update(
                {
                    auth_policy.id: AuthorizationPolicy(
                        id=auth_policy.id,
                        name=auth_policy.display_name,
                        description=auth_policy.description,
                        default_user_role_permissions=getattr(
                            auth_policy, "default_user_role_permissions", None
                        ),
                    )
                }
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return authorization_policy


class AuthorizationPolicy(BaseModel):
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions]

    class Config:
        arbitrary_types_allowed = True
