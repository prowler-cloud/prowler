from asyncio import gather, get_event_loop
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Entra(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)

        loop = get_event_loop()

        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
                self._get_conditional_access_policies(),
            )
        )

        self.authorization_policy = attributes[0]
        self.conditional_access_policies = attributes[1]

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

    async def _get_conditional_access_policies(self):
        logger.info("Entra - Getting conditional access policies...")

        conditional_access_policies = {}
        try:
            conditional_access_policies_list = (
                await self.client.identity.conditional_access.policies.get()
            )
            for policy in conditional_access_policies_list.value:
                conditional_access_policies[policy.id] = ConditionalAccessPolicy(
                    id=policy.id,
                    display_name=policy.display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[
                                application
                                for application in getattr(
                                    policy.conditions.applications,
                                    "include_applications",
                                    [],
                                )
                            ],
                            excluded_applications=[
                                application
                                for application in getattr(
                                    policy.conditions.applications,
                                    "exclude_applications",
                                    [],
                                )
                            ],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[
                                group
                                for group in getattr(
                                    policy.conditions.users,
                                    "include_groups",
                                    [],
                                )
                            ],
                            excluded_groups=[
                                group
                                for group in getattr(
                                    policy.conditions.users,
                                    "exclude_groups",
                                    [],
                                )
                            ],
                            included_users=[
                                user
                                for user in getattr(
                                    policy.conditions.users,
                                    "include_users",
                                    [],
                                )
                            ],
                            excluded_users=[
                                user
                                for user in getattr(
                                    policy.conditions.users,
                                    "exclude_users",
                                    [],
                                )
                            ],
                            included_roles=[
                                role
                                for role in getattr(
                                    policy.conditions.users,
                                    "include_roles",
                                    [],
                                )
                            ],
                            excluded_roles=[
                                role
                                for role in getattr(
                                    policy.conditions.users,
                                    "exclude_roles",
                                    [],
                                )
                            ],
                        ),
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=(
                                policy.session_controls.persistent_browser.is_enabled
                                if policy.session_controls
                                and policy.session_controls.persistent_browser
                                else False
                            ),
                            mode=(
                                policy.session_controls.persistent_browser.mode
                                if policy.session_controls
                                and policy.session_controls.persistent_browser
                                else "always"
                            ),
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=(
                                policy.session_controls.sign_in_frequency.is_enabled
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else False
                            ),
                            frequency=(
                                policy.session_controls.sign_in_frequency.value
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else None
                            ),
                        ),
                    ),
                    state=ConditionalAccessPolicyState(
                        getattr(policy, "state", "disabled")
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return conditional_access_policies


class ConditionalAccessPolicyState(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ENABLED_FOR_REPORTING = "enabledForReportingButNotEnforced"


class ApplicationsConditions(BaseModel):
    included_applications: List[str]
    excluded_applications: List[str]


class UsersConditions(BaseModel):
    included_groups: List[str]
    excluded_groups: List[str]
    included_users: List[str]
    excluded_users: List[str]
    included_roles: List[str]
    excluded_roles: List[str]


class Conditions(BaseModel):
    application_conditions: Optional[ApplicationsConditions]
    user_conditions: Optional[UsersConditions]


class PersistentBrowser(BaseModel):
    is_enabled: bool
    mode: str


class SignInFrequency(BaseModel):
    is_enabled: bool
    frequency: Optional[int]


class SessionControls(BaseModel):
    persistent_browser: PersistentBrowser
    sign_in_frequency: SignInFrequency


class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    conditions: Conditions
    session_controls: SessionControls
    state: ConditionalAccessPolicyState


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
