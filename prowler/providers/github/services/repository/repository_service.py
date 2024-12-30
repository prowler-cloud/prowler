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
                    if not repo.private:  # Only for testing purposes
                        default_branch = repo.default_branch
                        securitymd_exists = False
                        try:
                            securitymd_exists = (
                                repo.get_contents("SECURITY.md") is not None
                            )
                        except Exception as e:
                            logger.warning(
                                f"Could not find SECURITY.md for repo {repo.name}: {e}"
                            )

                        delete_branch_on_merge = (
                            repo.delete_branch_on_merge
                            if repo.delete_branch_on_merge is not None
                            else False
                        )

                        dependabot_status = False
                        try:
                            dependabot_status = (
                                repo.security_and_analysis.dependabot_security_updates.status
                                == "enabled"
                            )
                        except Exception as e:
                            logger.warning(
                                f"Could not determine dependabot status for repo {repo.name}: {e}"
                            )

                        branch_protection = None
                        try:
                            branch = repo.get_branch(default_branch)
                            if branch.protected:
                                protection = branch.get_protection()
                                if protection:
                                    require_pr = (
                                        protection.required_pull_request_reviews
                                        is not None
                                    )
                                    approval_cnt = (
                                        protection.required_pull_request_reviews.required_approving_review_count
                                        if require_pr
                                        else 0
                                    )

                                    linear_history = protection.required_linear_history
                                    allow_force_push = protection.allow_force_pushes
                                    allow_branch_deletion = protection.allow_deletions
                                    enforce_status_checks = (
                                        protection.required_status_checks.strict
                                        if protection.required_status_checks
                                        else False
                                    )
                                    enforce_admins = protection.enforce_admins
                                    conversation_resolution = (
                                        protection.required_conversation_resolution
                                    )

                                    branch_protection = Protection(
                                        require_pull_request=require_pr,
                                        approval_count=approval_cnt,
                                        linear_history=linear_history,
                                        allow_force_push=allow_force_push,
                                        allow_branch_deletion=allow_branch_deletion,
                                        enforce_status_checks=enforce_status_checks,
                                        enforce_admins=enforce_admins,
                                        conversation_resolution=conversation_resolution,
                                    )

                        except Exception as e:
                            logger.warning(
                                f"Could not get branch protection for repo {repo.name}: {e}"
                            )

                        repos[repo.id] = Repo(
                            id=repo.id,
                            name=repo.name,
                            full_name=repo.full_name,
                            default_branch=repo.default_branch,
                            private=repo.private,
                            securitymd=securitymd_exists,
                            default_branch_protection=branch_protection,
                            delete_branch_on_merge=delete_branch_on_merge,
                            dependabot_enabled=dependabot_status,
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return repos


class Protection(BaseModel):
    """Model for Github Branch Protection"""

    require_pull_request: bool = False
    approval_count: int = 0
    linear_history: bool = False
    allow_force_push: bool = True
    allow_branch_deletion: bool = True
    enforce_status_checks: bool = False
    enforce_admins: bool = False
    conversation_resolution: bool = False


class Repo(BaseModel):
    """Model for Github Repository"""

    id: int
    name: str
    full_name: str
    private: bool
    default_branch: str
    default_branch_protection: Optional[Protection]
    securitymd: bool = False
    delete_branch_on_merge: bool = False
    dependabot_enabled: bool = False
