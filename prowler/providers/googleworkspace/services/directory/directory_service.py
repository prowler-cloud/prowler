from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Directory(GoogleWorkspaceService):

    def __init__(self, provider):
        super().__init__(provider)
        self.users = self._list_users()

    def _list_users(self):
        logger.info("Directory - Listing Users...")
        users = {}

        try:
            # Build the Admin SDK Directory service
            service = self._build_service("admin", "directory_v1")

            if not service:
                logger.error("Failed to build Directory service")
                return users

            # Fetch users using the Directory API
            # Reference: https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list
            request = service.users().list(
                customer=self.provider.identity.customer_id,
                maxResults=500,  # Max allowed by API
                orderBy="email",
            )

            while request is not None:
                try:
                    response = request.execute()

                    for user_data in response.get("users", []):
                        user = User(
                            id=user_data.get("id"),
                            email=user_data.get("primaryEmail"),
                            full_name=user_data.get("name", {}).get("fullName", ""),
                            given_name=user_data.get("name", {}).get("givenName", ""),
                            family_name=user_data.get("name", {}).get("familyName", ""),
                            is_admin=user_data.get("isAdmin", False),
                            is_delegated_admin=user_data.get("isDelegatedAdmin", False),
                            is_suspended=user_data.get("suspended", False),
                            is_archived=user_data.get("archived", False),
                            creation_time=user_data.get("creationTime"),
                            last_login_time=user_data.get("lastLoginTime"),
                            organizational_unit=user_data.get("orgUnitPath", "/"),
                            is_mailbox_setup=user_data.get("isMailboxSetup", False),
                            customer_id=user_data.get("customerId"),
                        )
                        users[user.id] = user
                        logger.debug(
                            f"Processed user: {user.email} (Admin: {user.is_admin})"
                        )

                    request = service.users().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error, "listing users", self.provider.identity.customer_id
                    )
                    break

            logger.info(f"Found {len(users)} users in the domain")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users


class User(BaseModel):

    id: str
    email: str
    full_name: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    is_admin: bool = False
    is_delegated_admin: bool = False
    is_suspended: bool = False
    is_archived: bool = False
    creation_time: Optional[str] = None
    last_login_time: Optional[str] = None
    organizational_unit: str = "/"
    is_mailbox_setup: bool = False
    customer_id: Optional[str] = None
