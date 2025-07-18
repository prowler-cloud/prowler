from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService


class Organization(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.organizations = self._list_organizations()

    def _list_organizations(self):
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
                            except Exception as org_error:
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
                                    except Exception as user_error:
                                        logger.warning(
                                            f"'{org_name}' not accessible as organization or user: {user_error}"
                                        )
                                else:
                                    logger.warning(
                                        f"Organization '{org_name}' not accessible: {org_error}"
                                    )
                        except Exception as error:
                            logger.warning(f"Error accessing '{org_name}': {error}")
                elif not self.provider.repositories:
                    # Default behavior: get all organizations the user is a member of
                    # Only when no repositories are specified
                    for org in client.get_user().get_orgs():
                        self._process_organization(org, organizations)

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
