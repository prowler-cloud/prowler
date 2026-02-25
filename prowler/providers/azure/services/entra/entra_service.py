import asyncio
from asyncio import gather
from typing import List, Optional
from uuid import UUID

from msgraph import GraphServiceClient
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.config import GUEST_USER_ACCESS_NO_RESTRICTICTED
from prowler.providers.azure.lib.service.service import AzureService


class Entra(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(GraphServiceClient, provider)

        self.tenant_ids = provider.identity.tenant_ids

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
                "Cannot initialize Entra service while event loop is running"
            )

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

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

    async def _get_users(self):
        logger.info("Entra - Getting users...")
        users = {}
        try:
            for tenant, client in self.clients.items():
                users.update({tenant: {}})
                users_response = await client.users.get()
                registration_details = await self._get_user_registration_details(client)

                try:
                    while users_response:
                        for user in getattr(users_response, "value", []) or []:
                            users[tenant].update(
                                {
                                    user.id: User(
                                        id=user.id,
                                        name=user.display_name,
                                        is_mfa_capable=registration_details.get(
                                            user.id, False
                                        ),
                                    )
                                }
                            )

                        next_link = getattr(users_response, "odata_next_link", None)
                        if not next_link:
                            break
                        users_response = await client.users.with_url(next_link).get()

                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users

    async def _get_user_registration_details(self, client):
        registration_details = {}
        try:
            registration_builder = (
                client.reports.authentication_methods.user_registration_details
            )
            registration_response = await registration_builder.get()

            while registration_response:
                for detail in getattr(registration_response, "value", []) or []:
                    registration_details.update(
                        {detail.id: getattr(detail, "is_mfa_capable", False)}
                    )

                next_link = getattr(registration_response, "odata_next_link", None)
                if not next_link:
                    break
                registration_response = await registration_builder.with_url(
                    next_link
                ).get()

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return registration_details

    async def _get_authorization_policy(self):
        logger.info("Entra - Getting authorization policy...")

        authorization_policy = {}
        try:
            for tenant, client in self.clients.items():
                auth_policy = await client.policies.authorization_policy.get()

                default_user_role_permissions = getattr(
                    auth_policy, "default_user_role_permissions", None
                )

                authorization_policy.update(
                    {
                        tenant: AuthorizationPolicy(
                            id=auth_policy.id,
                            name=auth_policy.display_name,
                            description=auth_policy.description,
                            default_user_role_permissions=DefaultUserRolePermissions(
                                allowed_to_create_apps=getattr(
                                    default_user_role_permissions,
                                    "allowed_to_create_apps",
                                    None,
                                ),
                                allowed_to_create_security_groups=getattr(
                                    default_user_role_permissions,
                                    "allowed_to_create_security_groups",
                                    None,
                                ),
                                allowed_to_create_tenants=getattr(
                                    default_user_role_permissions,
                                    "allowed_to_create_tenants",
                                    None,
                                ),
                                allowed_to_read_bitlocker_keys_for_owned_device=getattr(
                                    default_user_role_permissions,
                                    "allowed_to_read_bitlocker_keys_for_owned_device",
                                    None,
                                ),
                                allowed_to_read_other_users=getattr(
                                    default_user_role_permissions,
                                    "allowed_to_read_other_users",
                                    None,
                                ),
                                odata_type=getattr(
                                    default_user_role_permissions, "odata_type", None
                                ),
                                permission_grant_policies_assigned=[
                                    policy_assigned
                                    for policy_assigned in getattr(
                                        default_user_role_permissions,
                                        "permission_grant_policies_assigned",
                                        [],
                                    )
                                ],
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
                                id=group_setting.id,
                                name=getattr(group_setting, "display_name", None),
                                template_id=getattr(group_setting, "template_id", None),
                                settings=[
                                    SettingValue(
                                        name=setting.name,
                                        odata_type=setting.odata_type,
                                        value=setting.value,
                                    )
                                    for setting in getattr(group_setting, "values", [])
                                ],
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
                                id=named_location.id,
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
                                    self.users[tenant][member.id]
                                    for member in directory_role_members.value
                                    if self.users[tenant].get(member.id, None)
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
                                id=policy.id,
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
    is_mfa_capable: bool = False


class DefaultUserRolePermissions(BaseModel):
    allowed_to_create_apps: Optional[bool] = None
    allowed_to_create_security_groups: Optional[bool] = None
    allowed_to_create_tenants: Optional[bool] = None
    allowed_to_read_bitlocker_keys_for_owned_device: Optional[bool] = None
    allowed_to_read_other_users: Optional[bool] = None
    odata_type: Optional[str] = None
    permission_grant_policies_assigned: Optional[List[str]] = None


class AuthorizationPolicy(BaseModel):
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions] = None
    guest_invite_settings: str
    guest_user_role_id: UUID


class SettingValue(BaseModel):
    name: Optional[str] = None
    odata_type: Optional[str] = None
    value: Optional[str] = None


class GroupSetting(BaseModel):
    id: str
    name: Optional[str] = None
    template_id: Optional[str] = None
    settings: List[SettingValue]


class SecurityDefault(BaseModel):
    id: str
    name: str
    is_enabled: bool


class NamedLocation(BaseModel):
    id: str
    name: str
    ip_ranges_addresses: List[str]
    is_trusted: bool


class DirectoryRole(BaseModel):
    id: str
    members: List[User]


class ConditionalAccessPolicy(BaseModel):
    id: str
    name: str
    state: str
    users: dict[str, List[str]]
    target_resources: dict[str, List[str]]
    access_controls: dict[str, List[str]]
