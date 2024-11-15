from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.lib.service.service import GithubService


class GitHubAccount(GithubService):
    def __init__(self, provider: GithubProvider):
        super().__init__("GitHubAccount", provider)
        self.account = Account(
            name=provider.identity.account_name, id=provider.identity.account_id
        )
        self._get_ssh_keys_status()

    def _get_ssh_keys_status(self):
        try:
            user = self.client.get_user()
            keys = self.client.get_user_keys(user.login)
            self.account.ssh_keys = keys.totalCount > 0

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Account(BaseModel):
    name: str
    id: str
    ssh_keys: bool = False
