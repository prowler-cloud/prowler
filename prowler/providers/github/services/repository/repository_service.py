from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService


class Repository(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.repositories = self._list_repositories()

    def _list_repositories(self):
        logger.info("Repository - Listing Repositories...")
        repos = {}
        try:
            for client in self.clients:
                for repo in client.get_user().get_repos():
                    try:
                        securitymd_exists = repo.get_contents("SECURITY.md") is not None
                        """
                        securitymd_exists = False
                        contents = repo.get_contents("")
                        while contents:
                            file_content = contents.pop(0)
                            if file_content.type == "dir":
                                contents.extend(repo.get_contents(file_content.path))
                            elif file_content.path.endswith("SECURITY.md"):
                                securitymd_exists = True
                                break
                        """
                    except Exception:
                        securitymd_exists = False
                    repos[repo.id] = Repo(
                        id=repo.id,
                        name=repo.name,
                        full_name=repo.full_name,
                        private=repo.private,
                        securitymd=securitymd_exists,
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return repos


class Repo(BaseModel):
    """Model for Github Repository"""

    id: int
    name: str
    full_name: str
    private: bool
    securitymd: Optional[bool] = False
