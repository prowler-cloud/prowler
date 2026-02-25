import asyncio
import json
from asyncio import gather
from enum import Enum
from typing import Dict, List, Optional
from uuid import UUID

from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import (
    RunHuntingQueryPostRequestBody,
)
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Entra(M365Service):
    """
    Microsoft Entra ID service class.

    This class provides methods to retrieve and manage Microsoft Entra ID
    security policies and configurations, including authorization policies,
    conditional access policies, admin consent policies, groups, organizations,
    users, and OAuth application data from Defender XDR.

    Attributes:
        tenant_domain (str): The tenant domain.
        authorization_policy (AuthorizationPolicy): The authorization policy.
        conditional_access_policies (dict): Dictionary of conditional access policies.
        admin_consent_policy (AdminConsentPolicy): The admin consent policy.
        groups (list): List of groups.
        organizations (list): List of organizations.
        users (dict): Dictionary of users.
        user_accounts_status (dict): Dictionary of user account statuses.
        oauth_apps (dict): Dictionary of OAuth applications from Defender XDR.
    """

    def __init__(self, provider: M365Provider):
        """
        Initialize the Entra service client.

        Args:
            provider: The M365Provider instance for authentication and configuration.
        """
        super().__init__(provider)

        if self.powershell:
            self.powershell.connect_exchange_online()
            self.user_accounts_status = self.powershell.get_user_account_status()
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
                "Cannot initialize Entra service while event loop is running"
            )

        self.tenant_domain = provider.identity.tenant_domain
        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
                self._get_conditional_access_policies(),
                self._get_admin_consent_policy(),
                self._get_groups(),
                self._get_organization(),
                self._get_users(),
                self._get_oauth_apps(),
                self._get_directory_sync_settings(),
            )
        )

        self.authorization_policy = attributes[0]
        self.conditional_access_policies = attributes[1]
        self.admin_consent_policy = attributes[2]
        self.groups = attributes[3]
        self.organizations = attributes[4]
        self.users = attributes[5]
        self.oauth_apps: Optional[Dict[str, OAuthApp]] = attributes[6]
        self.directory_sync_settings, self.directory_sync_error = attributes[7]
        self.user_accounts_status = {}

        if created_loop:
            asyncio.set_event_loop(None)
            loop.close()

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
                guest_invite_settings=auth_policy.allow_invites_from,
                guest_user_role_id=auth_policy.guest_user_role_id,
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
                            included_user_actions=[
                                UserAction(user_action)
                                for user_action in getattr(
                                    policy.conditions.applications,
                                    "include_user_actions",
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
                        client_app_types=[
                            ClientAppType(client_app_type)
                            for client_app_type in getattr(
                                policy.conditions,
                                "client_app_types",
                                [],
                            )
                        ],
                        user_risk_levels=[
                            RiskLevel(risk_level)
                            for risk_level in getattr(
                                policy.conditions,
                                "user_risk_levels",
                                [],
                            )
                        ],
                        sign_in_risk_levels=[
                            RiskLevel(risk_level)
                            for risk_level in getattr(
                                policy.conditions,
                                "sign_in_risk_levels",
                                [],
                            )
                        ],
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
                        authentication_strength=(
                            policy.grant_controls.authentication_strength.display_name
                            if policy.grant_controls is not None
                            and policy.grant_controls.authentication_strength
                            is not None
                            else None
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
                            type=(
                                SignInFrequencyType(
                                    policy.session_controls.sign_in_frequency.type
                                )
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                and policy.session_controls.sign_in_frequency.type
                                else None
                            ),
                            interval=(
                                SignInFrequencyInterval(
                                    policy.session_controls.sign_in_frequency.frequency_interval
                                )
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else None
                            ),
                        ),
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=(
                                policy.session_controls.application_enforced_restrictions.is_enabled
                                if policy.session_controls
                                and policy.session_controls.application_enforced_restrictions
                                else False
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

    async def _get_organization(self):
        logger.info("Entra - Getting organizations...")
        organizations = []
        try:
            org_data = await self.client.organization.get()
            for org in org_data.value:
                sync_enabled = (
                    org.on_premises_sync_enabled
                    if org.on_premises_sync_enabled is not None
                    else False
                )

                organization = Organization(
                    id=org.id,
                    name=org.display_name,
                    on_premises_sync_enabled=sync_enabled,
                )
                organizations.append(organization)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return organizations

    async def _get_directory_sync_settings(self):
        """Retrieve on-premises directory synchronization settings.

        Fetches the directory synchronization configuration from Microsoft Graph API
        to determine the state of synchronization features such as password sync,
        device writeback, and other hybrid identity settings.

        Returns:
            A tuple containing:
            - A list of DirectorySyncSettings objects, or an empty list if retrieval fails.
            - An error message string if there was an access error, None otherwise.
        """
        logger.info("Entra - Getting directory sync settings...")
        directory_sync_settings = []
        error_message = None
        try:
            sync_data = await self.client.directory.on_premises_synchronization.get()
            for sync in getattr(sync_data, "value", []) or []:
                features = getattr(sync, "features", None)
                directory_sync_settings.append(
                    DirectorySyncSettings(
                        id=sync.id,
                        password_sync_enabled=getattr(
                            features, "password_sync_enabled", False
                        )
                        or False,
                        seamless_sso_enabled=getattr(
                            features, "seamless_sso_enabled", False
                        )
                        or False,
                    )
                )
        except ODataError as error:
            error_code = getattr(error.error, "code", None) if error.error else None
            if error_code == "Authorization_RequestDenied":
                error_message = "Insufficient privileges to read directory sync settings. Required permission: OnPremDirectorySynchronization.Read.All or OnPremDirectorySynchronization.ReadWrite.All"
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error_message}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                error_message = str(error)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            error_message = str(error)
        return directory_sync_settings, error_message

    async def _get_users(self):
        logger.info("Entra - Getting users...")
        users = {}
        try:
            users_response = await self.client.users.get()
            directory_roles = await self.client.directory_roles.get()

            async def fetch_role_members(directory_role):
                members_response = (
                    await self.client.directory_roles.by_directory_role_id(
                        directory_role.id
                    ).members.get()
                )
                return directory_role.role_template_id, members_response.value

            tasks = [fetch_role_members(role) for role in directory_roles.value]
            roles_members_list = await asyncio.gather(*tasks)

            user_roles_map = {}
            for role_template_id, members in roles_members_list:
                for member in members:
                    user_roles_map.setdefault(member.id, []).append(role_template_id)

            registration_details = await self._get_user_registration_details()

            while users_response:
                for user in getattr(users_response, "value", []) or []:
                    users[user.id] = User(
                        id=user.id,
                        name=user.display_name,
                        on_premises_sync_enabled=(
                            True if (user.on_premises_sync_enabled) else False
                        ),
                        directory_roles_ids=user_roles_map.get(user.id, []),
                        is_mfa_capable=(registration_details.get(user.id, False)),
                        account_enabled=not self.user_accounts_status.get(
                            user.id, {}
                        ).get("AccountDisabled", False),
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

    async def _get_user_registration_details(self):
        registration_details = {}
        try:
            registration_builder = (
                self.client.reports.authentication_methods.user_registration_details
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
            if (
                error.__class__.__name__ == "ODataError"
                and error.__dict__.get("response_status_code", None) == 403
            ):
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return registration_details

    async def _get_oauth_apps(self) -> Optional[Dict[str, "OAuthApp"]]:
        """
        Retrieve OAuth applications from Defender XDR using Advanced Hunting.

        This method queries the OAuthAppInfo table to get information about
        OAuth applications registered in the tenant, including their permissions
        and usage status.

        Returns:
            Optional[Dict[str, OAuthApp]]: Dictionary of OAuth applications keyed by app ID,
                or None if the API call failed (missing permissions or App Governance not enabled).
        """
        logger.info("Entra - Getting OAuth apps from Defender XDR...")
        oauth_apps: Optional[Dict[str, OAuthApp]] = {}
        try:
            # Query the OAuthAppInfo table using Advanced Hunting
            # The query gets apps with their permissions including usage status
            query = """
OAuthAppInfo
| project OAuthAppId, AppName, AppStatus, PrivilegeLevel, Permissions,
          ServicePrincipalId, IsAdminConsented, LastUsedTime, AppOrigin
"""
            request_body = RunHuntingQueryPostRequestBody(query=query)

            result = await self.client.security.microsoft_graph_security_run_hunting_query.post(
                request_body
            )

            if result and result.results:
                for row in result.results:
                    row_data = row.additional_data
                    raw_app_id = row_data.get("OAuthAppId", "")
                    # Convert to string in case API returns non-string type
                    app_id = str(raw_app_id) if raw_app_id else ""
                    if not app_id:
                        continue

                    # Parse the permissions array
                    # Permissions can be a list of JSON strings or a list of dicts
                    permissions = []
                    raw_permissions = row_data.get("Permissions", [])
                    if raw_permissions:
                        for perm in raw_permissions:
                            # Parse JSON string if needed
                            if isinstance(perm, str):
                                try:
                                    perm = json.loads(perm)
                                except json.JSONDecodeError:
                                    continue
                            if isinstance(perm, dict):
                                permissions.append(
                                    OAuthAppPermission(
                                        name=str(perm.get("PermissionValue", "")),
                                        target_app_id=str(perm.get("TargetAppId", "")),
                                        target_app_name=str(
                                            perm.get("TargetAppDisplayName", "")
                                        ),
                                        permission_type=str(
                                            perm.get("PermissionType", "")
                                        ),
                                        classification=str(
                                            perm.get(
                                                "Classification",
                                                perm.get(
                                                    "PermissionClassification", ""
                                                ),
                                            )
                                        ),
                                        privilege_level=str(
                                            perm.get("PrivilegeLevel", "")
                                        ),
                                        usage_status=str(perm.get("InUse", "")),
                                    )
                                )

                    # Convert values to strings to handle API returning non-string types
                    raw_service_principal_id = row_data.get("ServicePrincipalId", "")
                    service_principal_id = (
                        str(raw_service_principal_id)
                        if raw_service_principal_id
                        else ""
                    )

                    raw_last_used_time = row_data.get("LastUsedTime")
                    last_used_time = (
                        str(raw_last_used_time)
                        if raw_last_used_time is not None
                        else None
                    )

                    oauth_apps[app_id] = OAuthApp(
                        id=app_id,
                        name=str(row_data.get("AppName", "")),
                        status=str(row_data.get("AppStatus", "")),
                        privilege_level=str(row_data.get("PrivilegeLevel", "")),
                        permissions=permissions,
                        service_principal_id=service_principal_id,
                        is_admin_consented=bool(
                            row_data.get("IsAdminConsented", False)
                        ),
                        last_used_time=last_used_time,
                        app_origin=str(row_data.get("AppOrigin", "")),
                    )

        except Exception as error:
            # Log the error and return None to indicate API failure
            # This API requires ThreatHunting.Read.All permission and App Governance to be enabled
            logger.warning(
                f"Entra - Could not retrieve OAuth apps from Defender XDR. "
                f"This requires ThreatHunting.Read.All permission and App Governance enabled. "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

        return oauth_apps


class ConditionalAccessPolicyState(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ENABLED_FOR_REPORTING = "enabledForReportingButNotEnforced"


class UserAction(Enum):
    REGISTER_SECURITY_INFO = "urn:user:registersecurityinfo"
    REGISTER_DEVICE = "urn:user:registerdevice"


class ApplicationsConditions(BaseModel):
    included_applications: List[str]
    excluded_applications: List[str]
    included_user_actions: List[UserAction]


class UsersConditions(BaseModel):
    included_groups: List[str]
    excluded_groups: List[str]
    included_users: List[str]
    excluded_users: List[str]
    included_roles: List[str]
    excluded_roles: List[str]


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    NO_RISK = "none"


class ClientAppType(Enum):
    ALL = "all"
    BROWSER = "browser"
    MOBILE_APPS_AND_DESKTOP_CLIENTS = "mobileAppsAndDesktopClients"
    EXCHANGE_ACTIVE_SYNC = "exchangeActiveSync"
    OTHER_CLIENTS = "other"


class Conditions(BaseModel):
    application_conditions: Optional[ApplicationsConditions]
    user_conditions: Optional[UsersConditions]
    client_app_types: Optional[List[ClientAppType]]
    user_risk_levels: List[RiskLevel] = []
    sign_in_risk_levels: List[RiskLevel] = []


class PersistentBrowser(BaseModel):
    is_enabled: bool
    mode: str


class SignInFrequencyInterval(Enum):
    TIME_BASED = "timeBased"
    EVERY_TIME = "everyTime"


class SignInFrequencyType(Enum):
    HOURS = "hours"
    DAYS = "days"


class SignInFrequency(BaseModel):
    is_enabled: bool
    frequency: Optional[int]
    type: Optional[SignInFrequencyType]
    interval: Optional[SignInFrequencyInterval]


class ApplicationEnforcedRestrictions(BaseModel):
    """Model representing application enforced restrictions session control."""

    is_enabled: bool = False


class SessionControls(BaseModel):
    """Model representing session controls for Conditional Access policies."""

    persistent_browser: PersistentBrowser
    sign_in_frequency: SignInFrequency
    application_enforced_restrictions: Optional[ApplicationEnforcedRestrictions] = None


class ConditionalAccessGrantControl(Enum):
    """
    Built-in grant controls for Conditional Access policies.
    Reference: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols
    """

    MFA = "mfa"
    BLOCK = "block"
    DOMAIN_JOINED_DEVICE = "domainJoinedDevice"
    PASSWORD_CHANGE = "passwordChange"
    COMPLIANT_DEVICE = "compliantDevice"
    APPROVED_APPLICATION = "approvedApplication"
    COMPLIANT_APPLICATION = "compliantApplication"
    TERMS_OF_USE = "termsOfUse"


class GrantControlOperator(Enum):
    AND = "AND"
    OR = "OR"


class GrantControls(BaseModel):
    built_in_controls: List[ConditionalAccessGrantControl]
    operator: GrantControlOperator
    authentication_strength: Optional[str]


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
    guest_invite_settings: Optional[str]
    guest_user_role_id: Optional[UUID]


class Organization(BaseModel):
    id: str
    name: str
    on_premises_sync_enabled: bool


class DirectorySyncSettings(BaseModel):
    """On-premises directory synchronization settings.

    Represents the synchronization configuration for a tenant, including feature
    flags that control hybrid identity behaviors such as password synchronization
    and Seamless SSO.
    """

    id: str
    password_sync_enabled: bool = False
    seamless_sso_enabled: bool = False


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


class User(BaseModel):
    id: str
    name: str
    on_premises_sync_enabled: bool
    directory_roles_ids: List[str] = []
    is_mfa_capable: bool = False
    account_enabled: bool = True


class InvitationsFrom(Enum):
    NONE = "none"
    ADMINS_AND_GUEST_INVITERS = "adminsAndGuestInviters"
    ADMINS_AND_GUEST_INVITERS_AND_MEMBERS = "adminsAndGuestInvitersAndAllMembers"
    EVERYONE = "everyone"


class AuthPolicyRoles(Enum):
    USER = UUID("a0b1b346-4d3e-4e8b-98f8-753987be4970")
    GUEST_USER = UUID("10dae51f-b6af-4016-8d66-8c2a99b929b3")
    GUEST_USER_ACCESS_RESTRICTED = UUID("2af84b1e-32c8-42b7-82bc-daa82404023b")


class OAuthAppPermission(BaseModel):
    """
    Model for OAuth application permission.

    Attributes:
        name: The permission name.
        target_app_id: The target application ID that provides this permission.
        target_app_name: The target application display name.
        permission_type: The type of permission (Application or Delegated).
        classification: Optional plane classification (e.g. Control Plane, Management Plane).
        privilege_level: The privilege level (High, Medium, Low).
        usage_status: The usage status (InUse or NotInUse).
    """

    name: str
    target_app_id: str = ""
    target_app_name: str = ""
    permission_type: str = ""
    classification: str = ""
    privilege_level: str = ""
    usage_status: str = ""


class OAuthApp(BaseModel):
    """
    Model for OAuth application from Defender XDR.

    Attributes:
        id: The application ID.
        name: The application display name.
        status: The application status (Enabled, Disabled, etc.).
        privilege_level: The overall privilege level of the app.
        permissions: List of permissions assigned to the app.
        service_principal_id: The service principal ID.
        is_admin_consented: Whether the app has admin consent.
        last_used_time: When the app was last used.
        app_origin: Whether the app is internal or external.
    """

    id: str
    name: str
    status: str = ""
    privilege_level: str = ""
    permissions: List[OAuthAppPermission] = []
    service_principal_id: str = ""
    is_admin_consented: bool = False
    last_used_time: Optional[str] = None
    app_origin: str = ""
