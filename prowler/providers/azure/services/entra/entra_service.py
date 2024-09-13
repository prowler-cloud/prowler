from asyncio import gather, get_event_loop
from dataclasses import dataclass
from typing import Any, List, Optional
from uuid import UUID

from msgraph import GraphServiceClient
from msgraph.generated.models.default_user_role_permissions import (
    DefaultUserRolePermissions,
)
from msgraph.generated.models.setting_value import SettingValue
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.config import GUEST_USER_ACCESS_NO_RESTRICTICTED
from prowler.providers.azure.lib.service.service import AzureService


class Entra(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(GraphServiceClient, provider)

        loop = get_event_loop()

        # Get users first alone because it is a dependency for other attributes
        self.users = loop.run_until_complete(self._get_users())

        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
                self._get_group_settings(),
                self._get_security_default(),
                self._get_named_locations(),
                self._get_directory_roles(),
                self._get_conditional_access_policy(),
            )
        )

        self.authorization_policy = attributes[0]
        self.group_settings = attributes[1]
        self.security_default = attributes[2]
        self.named_locations = attributes[3]
        self.directory_roles = attributes[4]
        self.conditional_access_policy = attributes[5]

    async def _get_users(self):
        logger.info("Entra - Getting users...")
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
            if (
                error.__class__.__name__ == "ODataError"
                and error.__dict__.get("response_status_code", None) == 403
            ):
                logger.error(
                    "You need 'UserAuthenticationMethod.Read.All' permission to access this information. It only can be granted through Service Principal authentication."
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return users

    async def _get_authorization_policy(self):
        logger.info("Entra - Getting authorization policy...")

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

    async def _get_group_settings(self):
        logger.info("Entra - Getting group settings...")
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

    async def _get_security_default(self):
        logger.info("Entra - Getting security default...")
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

    async def _get_named_locations(self):
        logger.info("Entra - Getting named locations...")
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

    async def _get_directory_roles(self):
        logger.info("Entra - Getting directory roles...")
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

    async def _get_conditional_access_policy(self):
        logger.info("Entra - Getting conditional access policy...")
        conditional_access_policy = {}
        try:
            for tenant, client in self.clients.items():
                conditional_access_policies = (
                    await client.identity.conditional_access.policies.get()
                )
                conditional_access_policy.update({tenant: {}})
                for policy in getattr(conditional_access_policies, "value", []):
                    conditions = getattr(policy, "conditions", None)

                    included_apps = []
                    excluded_apps = []

                    if getattr(conditions, "applications", None):
                        if getattr(conditions.applications, "include_applications", []):
                            included_apps = conditions.applications.include_applications
                        elif getattr(
                            conditions.applications, "include_user_actions", []
                        ):
                            included_apps = conditions.applications.include_user_actions

                        if getattr(conditions.applications, "exclude_applications", []):
                            excluded_apps = conditions.applications.exclude_applications
                        elif getattr(
                            conditions.applications, "exclude_user_actions", []
                        ):
                            excluded_apps = conditions.applications.exclude_user_actions

                    grant_access_controls = []
                    block_access_controls = []

                    for access_control in (
                        getattr(policy.grant_controls, "built_in_controls")
                        if policy.grant_controls
                        else []
                    ):
                        if "Grant" in str(access_control):
                            grant_access_controls.append(str(access_control))
                        else:
                            block_access_controls.append(str(access_control))

                    conditional_access_policy[tenant].update(
                        {
                            policy.id: ConditionalAccessPolicy(
                                name=policy.display_name,
                                state=getattr(policy, "state", "None"),
                                users={
                                    "include": (
                                        getattr(conditions.users, "include_users", [])
                                        if getattr(conditions, "users", None)
                                        else []
                                    ),
                                    "exclude": (
                                        getattr(conditions.users, "exclude_users", [])
                                        if getattr(conditions, "users", None)
                                        else []
                                    ),
                                },
                                target_resources={
                                    "include": included_apps,
                                    "exclude": excluded_apps,
                                },
                                access_controls={
                                    "grant": grant_access_controls,
                                    "block": block_access_controls,
                                },
                            )
                        }
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return conditional_access_policy


class User(BaseModel):
    id: str
    name: str
    authentication_methods: List[Any] = []


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
    settings: List[SettingValue]


class SecurityDefault(BaseModel):
    id: str
    name: str
    is_enabled: bool


class NamedLocation(BaseModel):
    name: str
    ip_ranges_addresses: List[str]
    is_trusted: bool


class DirectoryRole(BaseModel):
    id: str
    members: List[User]


class ConditionalAccessPolicy(BaseModel):
    name: str
    state: str
    users: dict[str, List[str]]
    target_resources: dict[str, List[str]]
    access_controls: dict[str, List[str]]
