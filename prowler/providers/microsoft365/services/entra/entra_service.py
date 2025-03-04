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
                    grant_controls=GrantControls(
                        built_in_controls=(
                            [
                                ConditionalAccessGrantControl(control.value)
                                for control in getattr(
                                    policy.grant_controls, "built_in_controls", {}
                                )
                            ]
                            if policy.grant_controls
                            else []
                        ),
                        operator=(
                            GrantControlOperator(
                                getattr(policy.grant_controls, "operator", "AND")
                            )
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


class ConditionalAccessGrantControl(Enum):
    MFA = "mfa"
    BLOCK = "block"
    DOMAIN_JOINED_DEVICE = "domainJoinedDevice"
    PASSWORD_CHANGE = "passwordChange"


class GrantControlOperator(Enum):
    AND = "AND"
    OR = "OR"


class GrantControls(BaseModel):
    built_in_controls: List[ConditionalAccessGrantControl]
    operator: GrantControlOperator


class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    conditions: Conditions
    session_controls: SessionControls
    grant_controls: GrantControls
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


class AdminRoles(Enum):
    APPLICATION_ADMINISTRATOR = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    AUTHENTICATION_ADMINISTRATOR = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    BILLING_ADMINISTRATOR = "b0f54661-2d74-4c50-afa3-1ec803f12efe"
    CLOUD_APPLICATION_ADMINISTRATOR = "158c047a-c907-4556-b7ef-446551a6b5f7"
    CONDITIONAL_ACCESS_ADMINISTRATOR = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    EXCHANGE_ADMINISTRATOR = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
    GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    HELPDESK_ADMINISTRATOR = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    PASSWORD_ADMINISTRATOR = "966707d0-3269-4727-9be2-8c3a10f19b9d"
    PRIVILEGED_AUTHENTICATION_ADMINISTRATOR = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
    PRIVILEGED_ROLE_ADMINISTRATOR = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    SECURITY_ADMINISTRATOR = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    SHAREPOINT_ADMINISTRATOR = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    USER_ADMINISTRATOR = "fe930be7-5e62-47db-91af-98c3a49a38b1"
