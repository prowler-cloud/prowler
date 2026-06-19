from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class User(BaseModel):
    """Model for a Linode account user."""

    username: str
    email: str = ""
    tfa_enabled: bool = False
    restricted: bool = False


class AccountService(LinodeService):
    """Service to interact with Linode Account Users."""

    def __init__(self, provider):
        super().__init__("account", provider)
        self.users: List[User] = []
        self._describe_users()

    def _describe_users(self):
        """Fetch all Linode account users."""
        try:
            raw_users = self.client.account.users()
            for user in raw_users:
                try:
                    self.users.append(
                        User(
                            username=getattr(user, "username", "") or "",
                            email=getattr(user, "email", "") or "",
                            tfa_enabled=getattr(user, "tfa_enabled", False) or False,
                            restricted=getattr(user, "restricted", False) or False,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"account - Error processing user {getattr(user, 'username', 'unknown')}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"account - Error fetching users: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
