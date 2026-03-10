import asyncio
from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class AdminCenter(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)

        self.organization_config = None
        self.sharing_policy = None
        if self.powershell:
            if self.powershell.connect_exchange_online():
                self.organization_config = self._get_organization_config()
                self.sharing_policy = self._get_sharing_policy()
            self.powershell.close()

        created_loop = False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created_loop = True

        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created_loop = True

        if loop.is_running():
            raise RuntimeError(
                "Cannot initialize AdminCenter service while event loop is running"
            )

        # Get users first alone because it is a dependency for other attributes
        self.users = loop.run_until_complete(self._get_users())

        attributes = loop.run_until_complete(
            asyncio.gather(
                self._get_directory_roles(),
                self._get_groups(),
                self._get_password_policy(),
            )
        )

        self.directory_roles = attributes[0]
        self.groups = attributes[1]
        self.password_policy = attributes[2]

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

    def _get_organization_config(self):
        logger.info("Microsoft365 - Getting Exchange Organization configuration...")
        organization_config = None
        try:
            organization_configuration = self.powershell.get_organization_config()
            if organization_configuration:
                organization_config = Organization(
                    name=organization_configuration.get("Name", ""),
                    guid=organization_configuration.get("Guid", ""),
                    customer_lockbox_enabled=organization_configuration.get(
                        "CustomerLockboxEnabled", False
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organization_config

    def _get_sharing_policy(self):
        logger.info("M365 - Getting sharing policy...")
        sharing_policy = None
        try:
            sharing_policy_data = self.powershell.get_sharing_policy()
            if sharing_policy_data:
                sharing_policy = SharingPolicy(
                    name=sharing_policy_data.get("Name", ""),
                    guid=sharing_policy_data.get("Guid", ""),
                    enabled=sharing_policy_data.get("Enabled", False),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return sharing_policy

    async def _get_users(self):
        logger.info("M365 - Getting users...")
        users = {}
        try:
            users.update({})
            users_response = await self.client.users.get()

            while users_response:
                for user in getattr(users_response, "value", []) or []:
                    license_details = await self.client.users.by_user_id(
                        user.id
                    ).license_details.get()
                    users.update(
                        {
                            user.id: User(
                                id=user.id,
                                name=getattr(user, "display_name", ""),
                                license=(
                                    getattr(
                                        license_details.value[0],
                                        "sku_part_number",
                                        None,
                                    )
                                    if license_details.value
                                    else None
                                ),
                            )
                        }
                    )

                next_link = getattr(users_response, "odata_next_link", None)
                if not next_link:
                    break
                users_response = await self.client.users.with_url(next_link).get()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users

    async def _get_directory_roles(self):
        logger.info("M365 - Getting directory roles...")
        directory_roles_with_members = {}
        try:
            directory_roles_with_members.update({})
            directory_roles = await self.client.directory_roles.get()
            for directory_role in directory_roles.value:
                directory_role_members = (
                    await self.client.directory_roles.by_directory_role_id(
                        directory_role.id
                    ).members.get()
                )
                members_with_roles = []
                for member in directory_role_members.value:
                    user = self.users.get(member.id, None)
                    if user:
                        user.directory_roles.append(directory_role.display_name)
                        members_with_roles.append(user)

                directory_roles_with_members.update(
                    {
                        directory_role.display_name: DirectoryRole(
                            id=directory_role.id,
                            name=directory_role.display_name,
                            members=members_with_roles,
                        )
                    }
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return directory_roles_with_members

    async def _get_groups(self):
        logger.info("M365 - Getting groups...")
        groups = {}
        try:
            groups_list = await self.client.groups.get()
            groups.update({})
            for group in groups_list.value:
                groups.update(
                    {
                        group.id: Group(
                            id=group.id,
                            name=getattr(group, "display_name", ""),
                            visibility=getattr(group, "visibility", ""),
                        )
                    }
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return groups

    async def _get_password_policy(self):
        logger.info("M365 - Getting password policy...")
        password_policy = None
        try:
            logger.info("M365 - Getting domains...")
            domains_list = await self.client.domains.get()
            for domain in getattr(domains_list, "value", []) or []:
                if not domain:
                    continue
                password_validity_period = getattr(
                    domain, "password_validity_period_in_days", None
                )
                if password_validity_period is None:
                    password_validity_period = 0

                password_policy = PasswordPolicy(
                    password_validity_period=password_validity_period,
                )
                break

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return password_policy


class User(BaseModel):
    id: str
    name: str
    directory_roles: List[str] = []
    license: Optional[str] = None
    user_type: Optional[str] = None


class DirectoryRole(BaseModel):
    id: str
    name: str
    members: List[User]


class Group(BaseModel):
    id: str
    name: str
    visibility: Optional[str]


class PasswordPolicy(BaseModel):
    password_validity_period: int


class Organization(BaseModel):
    name: str
    guid: str
    customer_lockbox_enabled: bool


class SharingPolicy(BaseModel):
    name: str
    guid: str
    enabled: bool
