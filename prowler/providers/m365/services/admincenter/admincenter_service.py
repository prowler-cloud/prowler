from asyncio import gather, get_event_loop
from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class AdminCenter(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        if self.powershell:
            self.powershell.close()

        self.organization_config = None
        self.sharing_policy = None
        if self.powershell:
            self.powershell.connect_exchange_online()
            self.organization_config = self._get_organization_config()
            self.sharing_policy = self._get_sharing_policy()
            self.powershell.close()

        loop = get_event_loop()

        # Get users first alone because it is a dependency for other attributes
        self.users = loop.run_until_complete(self._get_users())

        attributes = loop.run_until_complete(
            gather(
                self._get_directory_roles(),
                self._get_groups(),
                self._get_domains(),
            )
        )

        self.directory_roles = attributes[0]
        self.groups = attributes[1]
        self.domains = attributes[2]

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
            users_list = await self.client.users.get()
            users.update({})
            for user in users_list.value:
                license_details = await self.client.users.by_user_id(
                    user.id
                ).license_details.get()
                users.update(
                    {
                        user.id: User(
                            id=user.id,
                            name=user.display_name,
                            license=(
                                license_details.value[0].sku_part_number
                                if license_details.value
                                else None
                            ),
                        )
                    }
                )
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
                            name=group.display_name,
                            visibility=group.visibility,
                        )
                    }
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return groups

    async def _get_domains(self):
        logger.info("M365 - Getting domains...")
        domains = {}
        try:
            domains_list = await self.client.domains.get()
            domains.update({})
            for domain in domains_list.value:
                domains.update(
                    {
                        domain.id: Domain(
                            id=domain.id,
                            password_validity_period=domain.password_validity_period_in_days,
                        )
                    }
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return domains


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
    visibility: str


class Domain(BaseModel):
    id: str
    password_validity_period: int


class Organization(BaseModel):
    name: str
    guid: str
    customer_lockbox_enabled: bool


class SharingPolicy(BaseModel):
    name: str
    guid: str
    enabled: bool
