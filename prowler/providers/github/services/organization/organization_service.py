from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService


class Organization(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.organizations = self._list_organizations()

    def _list_organizations(self):
        logger.info("Organization - Listing Organizations...")
        organizations = {}
        try:
            for client in self.clients:
                for org in client.get_user().get_orgs():
                    organizations[org.id] = Org(
                        id=org.id,
                        name=org.login,
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organizations


class Org(BaseModel):
    """Model for Github Organization"""

    id: int
    name: str
