from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Directory(GoogleWorkspaceService):

    def __init__(self, provider):
        super().__init__(provider)
        self._service = self._build_service("admin", "directory_v1")
        self.users = self._list_users()
        self._roles = self._list_roles()
        self._populate_role_assignments()

    def _list_users(self):
        logger.info("Directory - Listing Users...")
        users = {}

        try:
            if not self._service:
                logger.error("Failed to build Directory service")
                return users

            # Fetch users using the Directory API
            # Reference: https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list
            request = self._service.users().list(
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
                            is_delegated_admin=user_data.get("isDelegatedAdmin", False),
                        )
                        users[user.id] = user
                        logger.debug(
                            f"Processed user: {user.email} (Admin: {user.is_admin})"
                        )

                    request = self._service.users().list_next(request, response)

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

    def _list_roles(self):
        logger.info("Directory - Listing Roles...")
        roles = {}

        try:
            if not self._service:
                return roles

            request = self._service.roles().list(
                customer=self.provider.identity.customer_id,
            )

            while request is not None:
                try:
                    response = request.execute()

                    for role_data in response.get("items", []):
                        role_id = str(role_data.get("roleId", ""))
                        role_name = role_data.get("roleName", "")
                        if role_id and role_name:
                            roles[role_id] = role_name

                    request = self._service.roles().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "listing roles",
                        self.provider.identity.customer_id,
                    )
                    break

            logger.info(f"Found {len(roles)} roles in the domain")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return roles

    def _populate_role_assignments(self):
        logger.info("Directory - Fetching Role Assignments for super admins...")

        if not self._service:
            return

        super_admins = [user for user in self.users.values() if user.is_admin]

        for user in super_admins:
            try:
                request = self._service.roleAssignments().list(
                    customer=self.provider.identity.customer_id,
                    userKey=user.id,
                )

                while request is not None:
                    try:
                        response = request.execute()

                        for assignment in response.get("items", []):
                            role_id = str(assignment.get("roleId", ""))
                            role_name = self._roles.get(role_id, f"Unknown ({role_id})")
                            user.role_assignments.append(role_name)

                        request = self._service.roleAssignments().list_next(
                            request, response
                        )

                    except Exception as error:
                        self._handle_api_error(
                            error,
                            "listing role assignments",
                            user.email,
                        )
                        break

                logger.debug(f"User {user.email} has roles: {user.role_assignments}")

            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class User(BaseModel):

    id: str
    email: str
    is_admin: bool = False
    is_delegated_admin: bool = False
    role_assignments: list[str] = []
