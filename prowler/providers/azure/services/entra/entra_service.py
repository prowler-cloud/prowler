import asyncio
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

from msgraph import GraphServiceClient
from msgraph.generated.models.default_user_role_permissions import (
    DefaultUserRolePermissions,
)
from msgraph.generated.models.setting_value import SettingValue
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


class Entra(AzureService):
    def __init__(self, azure_audit_info):
        super().__init__(GraphServiceClient, azure_audit_info)
        self.users = asyncio.get_event_loop().run_until_complete(self.__get_users__())
        self.authorization_policy = asyncio.get_event_loop().run_until_complete(
            self.__get_authorization_policy__()
        )
        self.group_settings = asyncio.get_event_loop().run_until_complete(
            self.__get_group_settings__()
        )
        self.security_default = asyncio.get_event_loop().run_until_complete(
            self.__get_security_default__()
        )
        self.named_locations = asyncio.get_event_loop().run_until_complete(
            self.__get_named_locations__()
        )
        self.directory_roles = asyncio.get_event_loop().run_until_complete(
            self.__get_directory_roles__()
        )

    async def __get_users__(self):
        users = {}
        try:
            for tenant, client in self.clients.items():
                users_list = await client.users.get()
                users.update({tenant: {}})
                for user in users_list.value:
                    users[tenant].update(
                        {
                            user.user_principal_name: User(
                                id=user.id,
                                name=user.display_name,
                                authentication_methods=(
                                    await client.users.by_user_id(
                                        user.id
                                    ).authentication.methods.get()
                                ).value,
                            )
                        }
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users

    async def __get_authorization_policy__(self):
        GUEST_USER_ACCESS_NO_RESTRICTICTED = UUID(
            "a0b1b346-4d3e-4e8b-98f8-753987be4970"
        )
        authorization_policy = {}
        try:
            for tenant, client in self.clients.items():
                auth_policy = await client.policies.authorization_policy.get()
                authorization_policy.update(
                    {
                        tenant: AuthorizationPolicy(
                            id=auth_policy.id,
                            name=auth_policy.display_name,
                            description=auth_policy.description,
                            default_user_role_permissions=getattr(
                                auth_policy, "default_user_role_permissions", None
                            ),
                            guest_invite_settings=(
                                auth_policy.allow_invites_from.value
                                if getattr(auth_policy, "allow_invites_from", None)
                                else "everyone"
                            ),
                            guest_user_role_id=getattr(
                                auth_policy,
                                "guest_user_role_id",
                                GUEST_USER_ACCESS_NO_RESTRICTICTED,
                            ),
                        )
                    }
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return authorization_policy

    async def __get_group_settings__(self):
        group_settings = {}
        try:
            for tenant, client in self.clients.items():
                group_settings_list = await client.group_settings.get()
                group_settings.update({tenant: {}})
                for group_setting in group_settings_list.value:
                    group_settings[tenant].update(
                        {
                            group_setting.id: GroupSetting(
                                name=getattr(group_setting, "display_name", None),
                                template_id=getattr(group_setting, "template_id", None),
                                settings=getattr(group_setting, "values", []),
                            )
                        }
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return group_settings

    async def __get_security_default__(self):
        try:
            security_defaults = {}
            for tenant, client in self.clients.items():
                security_default = (
                    await client.policies.identity_security_defaults_enforcement_policy.get()
                )
                security_defaults.update(
                    {
                        tenant: SecurityDefault(
                            id=security_default.id,
                            name=security_default.display_name,
                            is_enabled=security_default.is_enabled,
                        ),
                    }
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return security_defaults

    async def __get_named_locations__(self):
        named_locations = {}
        try:
            for tenant, client in self.clients.items():
                named_locations_list = (
                    await client.identity.conditional_access.named_locations.get()
                )
                named_locations.update({tenant: {}})
                for named_location in getattr(named_locations_list, "value", []):
                    named_locations[tenant].update(
                        {
                            named_location.id: NamedLocation(
                                name=named_location.display_name,
                                ip_ranges_addresses=[
                                    getattr(ip_range, "cidr_address", None)
                                    for ip_range in getattr(
                                        named_location, "ip_ranges", []
                                    )
                                ],
                                is_trusted=getattr(named_location, "is_trusted", False),
                            )
                        }
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return named_locations

    async def __get_directory_roles__(self):
        directory_roles_with_members = {}
        try:
            for tenant, client in self.clients.items():
                directory_roles_with_members.update({tenant: {}})
                directory_roles = await client.directory_roles.get()
                for directory_role in directory_roles.value:
                    directory_role_members = (
                        await client.directory_roles.by_directory_role_id(
                            directory_role.id
                        ).members.get()
                    )
                    directory_roles_with_members[tenant].update(
                        {
                            directory_role.display_name: DirectoryRole(
                                id=directory_role.id,
                                members=[
                                    self.users[tenant][member.user_principal_name]
                                    for member in directory_role_members.value
                                    if self.users[tenant].get(
                                        member.user_principal_name, None
                                    )
                                ],
                            )
                        }
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return directory_roles_with_members


class User(BaseModel):
    id: str
    name: str
    authentication_methods: list[Any] = []


@dataclass
class AuthorizationPolicy:
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions]
    guest_invite_settings: str
    guest_user_role_id: UUID


@dataclass
class GroupSetting:
    name: Optional[str]
    template_id: Optional[str]
    settings: list[SettingValue]


class SecurityDefault(BaseModel):
    id: str
    name: str
    is_enabled: bool


class NamedLocation(BaseModel):
    name: str
    ip_ranges_addresses: list[str]
    is_trusted: bool


class DirectoryRole(BaseModel):
    id: str
    members: list[User]
