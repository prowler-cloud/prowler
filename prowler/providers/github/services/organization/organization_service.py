from typing import Optional

import github
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService


class Organization(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.organizations = self._list_organizations()

    def _list_organizations(self):
        """
        List organizations based on provider scoping configuration.

        Scoping behavior:
        - No scoping: Returns all organizations for authenticated user
        - Organization scoping: Returns only specified organizations
          Example: --organization org1 org2
        - Repository + Organization scoping: Returns specified organizations + repository owners
          Example: --repository owner1/repo1 --organization org2
        - Repository only: Returns empty (no organization checks)
          Example: --repository owner1/repo1

        Returns:
            dict: Dictionary of organization ID to Org objects

        Raises:
            github.GithubException: When GitHub API access fails
            github.RateLimitExceededException: When API rate limits are exceeded
        """
        logger.info("Organization - Listing Organizations...")
        organizations = {}
        org_names_to_check = set()

        try:
            for client in self.clients:
                if self.provider.organizations:
                    org_names_to_check.update(self.provider.organizations)

                # If repositories are specified without organizations, don't perform organization checks
                # Only add repository owners to organization checks if organizations are also specified
                if self.provider.repositories and self.provider.organizations:
                    for repo_name in self.provider.repositories:
                        if "/" in repo_name:
                            owner_name = repo_name.split("/")[0]
                            org_names_to_check.add(owner_name)
                            logger.info(
                                f"Adding owner '{owner_name}' from repository '{repo_name}' to organization check list"
                            )

                # If specific organizations/owners are specified, check them directly
                if org_names_to_check:
                    for org_name in org_names_to_check:
                        try:
                            try:
                                org = client.get_organization(org_name)
                                self._process_organization(org, organizations)
                            except github.GithubException as org_error:
                                # If organization fails, try as a user (personal account)
                                if "404" in str(org_error):
                                    logger.info(
                                        f"'{org_name}' not found as organization, trying as user..."
                                    )
                                    try:
                                        user = client.get_user(org_name)
                                        # Create a pseudo-organization for the user
                                        organizations[user.id] = Org(
                                            id=user.id,
                                            name=user.login,
                                            mfa_required=None,  # Users don't have MFA requirements like orgs
                                        )
                                        logger.info(
                                            f"Added user '{user.login}' as organization for checks"
                                        )
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
                elif not self.provider.repositories:
                    # Default behavior: get all organizations the user is a member of
                    # Only when no repositories are specified
                    for org in client.get_user().get_orgs():
                        self._process_organization(org, organizations)

        except github.RateLimitExceededException as error:
            logger.error(f"GitHub API rate limit exceeded: {error}")
            raise  # Re-raise rate limit errors as they need special handling
        except github.GithubException as error:
            logger.error(f"GitHub API error while listing organizations: {error}")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organizations

    def _process_organization(self, org, organizations):
        """Process a single organization and extract its information."""
        try:
            require_mfa = org.two_factor_requirement_enabled
        except Exception as error:
            require_mfa = None
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        organizations[org.id] = Org(
            id=org.id,
            name=org.login,
            mfa_required=require_mfa,
        )


class Org(BaseModel):
    """Model for Github Organization"""

    id: int
    name: str
    mfa_required: Optional[bool] = False
