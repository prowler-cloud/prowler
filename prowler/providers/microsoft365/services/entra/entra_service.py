from asyncio import gather, get_event_loop
from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Entra(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)

        loop = get_event_loop()
        self.tenant_domain = provider.identity.tenant_domain
        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
                self._get_groups(),
                self._get_admin_consent_policy(),
            )
        )

        self.authorization_policy = attributes[0]
        self.groups = attributes[1]
        self.admin_consent_policy = attributes[2]

    async def _get_authorization_policy(self):
        logger.info("Entra - Getting authorization policy...")

        authorization_policy = None
        try:
            auth_policy = await self.client.policies.authorization_policy.get()

            default_user_role_permissions = getattr(
                auth_policy, "default_user_role_permissions", None
            )

            authorization_policy = AuthorizationPolicy(
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
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return authorization_policy

    async def _get_groups(self):
        logger.info("Entra - Getting groups...")
        groups = []
        try:
            groups_data = await self.client.groups.get()
            for group in groups_data.value:
                groups.append(
                    Group(
                        id=group.id,
                        name=group.display_name,
                        groupTypes=group.group_types,
                        membershipRule=group.membership_rule,
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return groups

    async def _get_admin_consent_policy(self):
        logger.info("Entra - Getting group settings...")
        admin_consent_policy = None
        try:
            policy = await self.client.policies.admin_consent_request_policy.get()
            admin_consent_policy = AdminConsentPolicy(
                admin_consent_enabled=policy.is_enabled,
                notify_reviewers=policy.notify_reviewers,
                email_reminders_to_reviewers=policy.reminders_enabled,
                duration_in_days=policy.request_duration_in_days,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return admin_consent_policy


class DefaultUserRolePermissions(BaseModel):
    allowed_to_create_apps: Optional[bool]
    allowed_to_create_security_groups: Optional[bool]
    allowed_to_create_tenants: Optional[bool]
    allowed_to_read_bitlocker_keys_for_owned_device: Optional[bool]
    allowed_to_read_other_users: Optional[bool]
    odata_type: Optional[str]
    permission_grant_policies_assigned: Optional[List[str]] = None


class AuthorizationPolicy(BaseModel):
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions]


class Group(BaseModel):
    id: str
    name: str
    groupTypes: List[str]
    membershipRule: Optional[str]


class AdminConsentPolicy(BaseModel):
    admin_consent_enabled: bool
    notify_reviewers: bool
    email_reminders_to_reviewers: bool
    duration_in_days: int
