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
                    delete_branch_on_merge = (
                        repo.delete_branch_on_merge
                        if repo.delete_branch_on_merge is not None
                        else False
                    )

                    require_pr = False
                    approval_cnt = 0
                    branch_protection = False
                    required_linear_history = False
                    allow_force_pushes = True
                    branch_deletion = True
                    require_code_owner_reviews = False
                    status_checks = False
                    enforce_admins = False
                    conversation_resolution = False
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
                                status_checks = (
                                    protection.required_status_checks is not None
                                )
                                enforce_admins = protection.enforce_admins
                                conversation_resolution = (
                                    protection.required_conversation_resolution
                                )
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
                            status_checks = None
                            enforce_admins = None
                            conversation_resolution = None
                            logger.error(
                                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )

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
                        status_checks=status_checks,
                        enforce_admins=enforce_admins,
                        conversation_resolution=conversation_resolution,
                        default_branch_protection=branch_protection,
                        codeowners_exists=codeowners_exists,
                        require_code_owner_reviews=require_code_owner_reviews,
                        delete_branch_on_merge=delete_branch_on_merge,
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
    status_checks: Optional[bool]
    enforce_admins: Optional[bool]
    approval_count: Optional[int]
    codeowners_exists: Optional[bool]
    require_code_owner_reviews: Optional[bool]
    delete_branch_on_merge: Optional[bool]
    conversation_resolution: Optional[bool]
