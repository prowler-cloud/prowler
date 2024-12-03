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
                    default_branch = repo.default_branch
                    try:
                        securitymd_exists = repo.get_contents("SECURITY.md") is not None
                    except Exception:
                        securitymd_exists = False

                    branch = repo.get_branch(default_branch)
                    require_pr = False
                    approval_cnt = 0
                    if branch.protected:
                        try:
                            protection = branch.get_protection()
                            if protection:
                                require_pr = (
                                    protection.required_pull_request_reviews is not None
                                )
                                approval_cnt = (
                                    protection.required_pull_request_reviews.required_approving_review_count
                                    if require_pr
                                    else 0
                                )
                        except Exception:
                            require_pr = False
                            approval_cnt = 0

                    repos[repo.id] = Repo(
                        id=repo.id,
                        name=repo.name,
                        full_name=repo.full_name,
                        default_branch=repo.default_branch,
                        private=repo.private,
                        securitymd=securitymd_exists,
                        require_pull_request=require_pr,
                        approval_count=approval_cnt,
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
    default_branch: str
    private: bool
    securitymd: Optional[bool] = False
    require_pull_request: Optional[bool] = False
    approval_count: Optional[int] = 0
