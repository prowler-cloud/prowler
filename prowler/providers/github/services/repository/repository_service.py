from datetime import datetime
from typing import Optional

import github
from pydantic.v1 import BaseModel

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

    def _validate_repository_format(self, repo_name: str) -> bool:
        """
        Validate repository name format.

        Args:
            repo_name: Repository name to validate

        Returns:
            bool: True if format is valid, False otherwise
        """
        if not repo_name or "/" not in repo_name:
            return False

        parts = repo_name.split("/")
        if len(parts) != 2:
            return False

        owner, repo = parts
        # Ensure both owner and repo names are non-empty
        if not owner.strip() or not repo.strip():
            return False

        return True

    def _list_repositories(self):
        """
        List repositories based on provider scoping configuration.

        Scoping behavior:
        - No scoping: Returns all accessible repositories for authenticated user
        - Repository scoping: Returns only specified repositories
          Example: --repository owner1/repo1 owner2/repo2
        - Organization scoping: Returns all repositories from specified organizations
          Example: --organization org1 org2
        - Combined scoping: Returns specified repositories + all repos from organizations
          Example: --repository owner1/repo1 --organization org2

        Returns:
            dict: Dictionary of repository ID to Repo objects

        Raises:
            github.GithubException: When GitHub API access fails
            github.RateLimitExceededException: When API rate limits are exceeded
        """
        logger.info("Repository - Listing Repositories...")
        repos = {}
        try:
            for client in self.clients:
                if self.provider.repositories or self.provider.organizations:
                    if self.provider.repositories:
                        logger.info(
                            f"Filtering for specific repositories: {self.provider.repositories}"
                        )
                        for repo_name in self.provider.repositories:
                            if not self._validate_repository_format(repo_name):
                                logger.warning(
                                    f"Repository name '{repo_name}' should be in 'owner/repo-name' format. Skipping."
                                )
                                continue
                            try:
                                repo = client.get_repo(repo_name)
                                self._process_repository(repo, repos)
                            except github.GithubException as error:
                                if "404" in str(error):
                                    logger.warning(
                                        f"Repository '{repo_name}' not found or not accessible"
                                    )
                                elif "403" in str(error):
                                    logger.warning(
                                        f"Access denied to repository '{repo_name}' - insufficient permissions"
                                    )
                                else:
                                    logger.error(
                                        f"GitHub API error for repository '{repo_name}': {error}"
                                    )
                            except github.RateLimitExceededException as error:
                                logger.error(
                                    f"Rate limit exceeded while accessing repository '{repo_name}': {error}"
                                )
                                raise  # Re-raise rate limit errors as they need special handling
                            except Exception as error:
                                logger.error(
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )

                    if self.provider.organizations:
                        logger.info(
                            f"Filtering for repositories in organizations: {self.provider.organizations}"
                        )
                        for org_name in self.provider.organizations:
                            try:
                                try:
                                    org = client.get_organization(org_name)
                                    for repo in org.get_repos():
                                        self._process_repository(repo, repos)
                                except github.GithubException as org_error:
                                    # If organization fails, try as a user
                                    if "404" in str(org_error):
                                        logger.info(
                                            f"'{org_name}' not found as organization, trying as user..."
                                        )
                                        try:
                                            user = client.get_user(org_name)
                                            for repo in user.get_repos():
                                                self._process_repository(repo, repos)
                                        except github.GithubException as user_error:
                                            if "404" in str(user_error):
                                                logger.warning(
                                                    f"'{org_name}' not found as organization or user"
                                                )
                                            elif "403" in str(user_error):
                                                logger.warning(
                                                    f"Access denied to '{org_name}' - insufficient permissions"
                                                )
                                            else:
                                                logger.warning(
                                                    f"GitHub API error accessing '{org_name}' as user: {user_error}"
                                                )
                                        except Exception as user_error:
                                            logger.error(
                                                f"{user_error.__class__.__name__}[{user_error.__traceback__.tb_lineno}]: {user_error}"
                                            )
                                    elif "403" in str(org_error):
                                        logger.warning(
                                            f"Access denied to organization '{org_name}' - insufficient permissions"
                                        )
                                    else:
                                        logger.error(
                                            f"GitHub API error accessing organization '{org_name}': {org_error}"
                                        )
                            except github.RateLimitExceededException as error:
                                logger.error(
                                    f"Rate limit exceeded while processing organization '{org_name}': {error}"
                                )
                                raise  # Re-raise rate limit errors as they need special handling
                            except Exception as error:
                                logger.error(
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                else:
                    for repo in client.get_user().get_repos():
                        self._process_repository(repo, repos)
        except github.RateLimitExceededException as error:
            logger.error(f"GitHub API rate limit exceeded: {error}")
            raise  # Re-raise rate limit errors as they need special handling
        except github.GithubException as error:
            logger.error(f"GitHub API error while listing repositories: {error}")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return repos

    def _process_repository(self, repo, repos):
        """Process a single repository and extract all its information."""
        default_branch = repo.default_branch
        securitymd_exists = self._file_exists(repo, "SECURITY.md")
        # CODEOWNERS file can be in .github/, root, or docs/
        # https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
        codeowners_paths = [
            ".github/CODEOWNERS",
            "CODEOWNERS",
            "docs/CODEOWNERS",
        ]
        codeowners_files = [self._file_exists(repo, path) for path in codeowners_paths]
        if True in codeowners_files:
            codeowners_exists = True
        elif all(file is None for file in codeowners_files):
            codeowners_exists = None
        else:
            codeowners_exists = False
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
        require_signed_commits = False
        status_checks = False
        enforce_admins = False
        conversation_resolution = False
        try:
            branch = repo.get_branch(default_branch)
            if branch.protected:
                protection = branch.get_protection()
                if protection:
                    require_pr = protection.required_pull_request_reviews is not None
                    approval_cnt = (
                        protection.required_pull_request_reviews.required_approving_review_count
                        if require_pr
                        else 0
                    )
                    required_linear_history = protection.required_linear_history
                    allow_force_pushes = protection.allow_force_pushes
                    branch_deletion = protection.allow_deletions
                    status_checks = protection.required_status_checks is not None
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
                    require_signed_commits = branch.get_required_signatures()
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
                require_signed_commits = None
                status_checks = None
                enforce_admins = None
                conversation_resolution = None
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        secret_scanning_enabled = False
        dependabot_alerts_enabled = False
        try:
            if (
                repo.security_and_analysis
                and repo.security_and_analysis.secret_scanning
            ):
                secret_scanning_enabled = (
                    repo.security_and_analysis.secret_scanning.status == "enabled"
                )
            try:
                # Use get_dependabot_alerts to check if Dependabot alerts are enabled
                repo.get_dependabot_alerts().totalCount
                # If the call succeeds, Dependabot is enabled (even if no alerts)
                dependabot_alerts_enabled = True
            except Exception as error:
                error_str = str(error)
                if (
                    "403" in error_str
                    and "Dependabot alerts are disabled for this repository."
                    in error_str
                ):
                    dependabot_alerts_enabled = False
                else:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    dependabot_alerts_enabled = None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            secret_scanning_enabled = None
            dependabot_alerts_enabled = None
        repos[repo.id] = Repo(
            id=repo.id,
            name=repo.name,
            owner=repo.owner.login,
            full_name=repo.full_name,
            default_branch=Branch(
                name=default_branch,
                protected=branch_protection,
                default_branch=True,
                require_pull_request=require_pr,
                approval_count=approval_cnt,
                required_linear_history=required_linear_history,
                allow_force_pushes=allow_force_pushes,
                branch_deletion=branch_deletion,
                status_checks=status_checks,
                enforce_admins=enforce_admins,
                conversation_resolution=conversation_resolution,
                require_code_owner_reviews=require_code_owner_reviews,
                require_signed_commits=require_signed_commits,
            ),
            private=repo.private,
            archived=repo.archived,
            pushed_at=repo.pushed_at,
            securitymd=securitymd_exists,
            codeowners_exists=codeowners_exists,
            secret_scanning_enabled=secret_scanning_enabled,
            dependabot_alerts_enabled=dependabot_alerts_enabled,
            delete_branch_on_merge=delete_branch_on_merge,
        )


class Branch(BaseModel):
    """Model for Github Branch"""

    name: str
    protected: bool
    default_branch: bool
    require_pull_request: Optional[bool]
    approval_count: Optional[int]
    required_linear_history: Optional[bool]
    allow_force_pushes: Optional[bool]
    branch_deletion: Optional[bool]
    status_checks: Optional[bool]
    enforce_admins: Optional[bool]
    require_code_owner_reviews: Optional[bool]
    require_signed_commits: Optional[bool]
    conversation_resolution: Optional[bool]


class Repo(BaseModel):
    """Model for Github Repository"""

    id: int
    name: str
    owner: str
    full_name: str
    default_branch: Branch
    private: bool
    archived: bool
    pushed_at: datetime
    securitymd: Optional[bool]
    codeowners_exists: Optional[bool]
    secret_scanning_enabled: Optional[bool]
    dependabot_alerts_enabled: Optional[bool]
    delete_branch_on_merge: Optional[bool]
