from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService


class Repository(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.repositories = self._list_repositories()

    def _file_exists(self, repo, filename):
        """Check if a file exists in the repository. Returns True if exists, False if not, None if error."""
        try:
            return repo.get_contents(filename) is not None
        except Exception as error:
            if "404" in str(error):
                return False
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                return None

    def _list_repositories(self):
        logger.info("Repository - Listing Repositories...")
        repos = {}
        try:
            for client in self.clients:
                for repo in client.get_user().get_repos():
                    default_branch = repo.default_branch
                    securitymd_exists = self._file_exists(repo, "SECURITY.md")
                    # CODEOWNERS file can be in .github/, root, or docs/
                    # https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
                    codeowners_paths = [
                        ".github/CODEOWNERS",
                        "CODEOWNERS",
                        "docs/CODEOWNERS",
                    ]
                    codeowners_exists = False
                    for path in codeowners_paths:
                        if self._file_exists(repo, path):
                            codeowners_exists = True
                            break
                    require_pr = False
                    approval_cnt = 0
                    branch_protection = False
                    required_linear_history = False
                    allow_force_pushes = True
                    branch_deletion = True
                    require_code_owner_reviews = False
                    try:
                        branch = repo.get_branch(default_branch)
                        if branch.protected:
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
                                required_linear_history = (
                                    protection.required_linear_history
                                )
                                allow_force_pushes = protection.allow_force_pushes
                                branch_deletion = protection.allow_deletions
                                branch_protection = True
                                require_code_owner_reviews = (
                                    protection.required_pull_request_reviews.require_code_owner_reviews
                                    if require_pr
                                    else False
                                )
                    except Exception as error:
                        # If the branch is not found, it is not protected
                        if "404" in str(error):
                            logger.warning(
                                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                        # Any other error, we cannot know if the branch is protected or not
                        else:
                            require_pr = None
                            approval_cnt = None
                            branch_protection = None
                            required_linear_history = None
                            allow_force_pushes = None
                            branch_deletion = None
                            require_code_owner_reviews = None
                            logger.error(
                                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )

                    secret_scanning_enabled = False
                    dependabot_alerts_enabled = False
                    try:
                        if repo.security_and_analysis:
                            secret_scanning_enabled = (
                                repo.security_and_analysis.secret_scanning.status
                                == "enabled"
                            )
                        try:
                            # Use get_dependabot_alerts to check if Dependabot alerts are enabled,
                            #   but this is slow because it retries 403 errors.
                            repo.get_dependabot_alerts()[0]
                            # If the call succeeds, Dependabot is enabled (even if no alerts)
                            dependabot_alerts_enabled = True
                        except Exception as dependabot_error:
                            error_str = str(dependabot_error)
                            if (
                                "403" in error_str
                                and "Dependabot alerts are disabled for this repository."
                                in error_str
                            ):
                                dependabot_alerts_enabled = False
                            elif "403" in error_str or "404" in error_str:
                                dependabot_alerts_enabled = None
                            else:
                                logger.error(
                                    f"Dependabot detection error in repo {repo.name}: {dependabot_error}"
                                )
                                dependabot_alerts_enabled = None
                    except Exception as error:
                        logger.error(
                            f"Secret scanning or Dependabot detection error in repo {repo.name}: {error}"
                        )
                        secret_scanning_enabled = None
                        dependabot_alerts_enabled = None
                    repos[repo.id] = Repo(
                        id=repo.id,
                        name=repo.name,
                        full_name=repo.full_name,
                        default_branch=repo.default_branch,
                        private=repo.private,
                        securitymd=securitymd_exists,
                        require_pull_request=require_pr,
                        approval_count=approval_cnt,
                        required_linear_history=required_linear_history,
                        allow_force_pushes=allow_force_pushes,
                        default_branch_deletion=branch_deletion,
                        default_branch_protection=branch_protection,
                        codeowners_exists=codeowners_exists,
                        require_code_owner_reviews=require_code_owner_reviews,
                        secret_scanning_enabled=secret_scanning_enabled,
                        dependabot_alerts_enabled=dependabot_alerts_enabled,
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
    default_branch_protection: Optional[bool]
    default_branch: str
    private: bool
    securitymd: Optional[bool]
    require_pull_request: Optional[bool]
    required_linear_history: Optional[bool]
    allow_force_pushes: Optional[bool]
    default_branch_deletion: Optional[bool]
    approval_count: Optional[int]
    codeowners_exists: Optional[bool]
    require_code_owner_reviews: Optional[bool]
    secret_scanning_enabled: Optional[bool]
    dependabot_alerts_enabled: Optional[bool]
