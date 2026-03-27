from pydantic import BaseModel

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
                            is_admin=user_data.get("isAdmin", False),
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
    is_admin: bool = False
