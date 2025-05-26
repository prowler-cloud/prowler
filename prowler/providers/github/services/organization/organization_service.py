from datetime import datetime
from typing import Optional

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
                    try:
                        require_mfa = org.two_factor_requirement_enabled
                    except Exception as error:
                        require_mfa = None
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

                    members = self._get_organization_members_with_activity(client, org)

                    organizations[org.id] = Org(
                        id=org.id,
                        name=org.login,
                        mfa_required=require_mfa,
                        members=members,
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organizations

    def _get_organization_members_with_activity(self, client, org):
        """Get organization members with their last activity information."""
        members = []
        try:
            for member in org.get_members():
                try:
                    last_activity = self._get_user_last_activity(client, member.login)

                    members.append(
                        OrgMember(
                            id=member.id,
                            login=member.login,
                            last_activity=last_activity,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    members.append(
                        OrgMember(
                            id=member.id,
                            login=member.login,
                            last_activity=None,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return members

    def _get_user_last_activity(self, client, username):
        """Get the last activity date for a user based on their recent events."""
        try:
            user = client.get_user(username)
            events = user.get_events()

            # Get the first (most recent) event
            try:
                latest_event = events[0]
                return latest_event.created_at
            except (IndexError, StopIteration):
                # No events found - user has no recent activity
                return None

        except Exception as error:
            logger.error(
                f"Error getting events for user {username}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


class OrgMember(BaseModel):
    """Model for Github Organization Member"""

    id: int
    login: str
    last_activity: Optional[datetime] = None


class Org(BaseModel):
    """Model for Github Organization"""

    id: int
    name: str
    mfa_required: Optional[bool] = False
    members: list[OrgMember] = []
