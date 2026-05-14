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
                        )
                        users[user.id] = user
                        logger.debug(f"Processed user: {user.email}")

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
                            roles[role_id] = Role(
                                id=role_id,
                                name=role_name,
                                description=role_data.get("roleDescription", ""),
                                is_super_admin_role=role_data.get(
                                    "isSuperAdminRole", False
                                ),
                            )

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
        logger.info("Directory - Fetching Role Assignments...")

        if not self._service:
            return

        try:
            request = self._service.roleAssignments().list(
                customer=self.provider.identity.customer_id,
            )

            while request is not None:
                try:
                    response = request.execute()

                    for assignment in response.get("items", []):
                        user_id = str(assignment.get("assignedTo", ""))
                        role_id = str(assignment.get("roleId", ""))
                        user = self.users.get(user_id)
                        role = self._roles.get(role_id)
                        if user and role:
                            user.role_assignments.append(role)
                            if role.is_super_admin_role:
                                user.is_admin = True

                    request = self._service.roleAssignments().list_next(
                        request, response
                    )

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "listing role assignments",
                        self.provider.identity.customer_id,
                    )
                    break

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Role(BaseModel):

    id: str
    name: str
    description: str = ""
    is_super_admin_role: bool = False


class User(BaseModel):

    id: str
    email: str
    is_admin: bool = False
    role_assignments: list[Role] = []
