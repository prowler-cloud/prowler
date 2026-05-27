from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate
from prowler.providers.okta.lib.service.service import OktaService

# External-directory IdP `type` values that delegate user sourcing to a
# separate identity store. When any of these is present and ACTIVE, the
# STIG's 35-day inactivity disable requirement is N/A on the Okta side —
# the connected directory is expected to enforce it instead.
EXTERNAL_DIRECTORY_IDP_TYPES = {"ACTIVE_DIRECTORY", "LDAP"}

# Okta exposes "Workflow > Automations" as USER_LIFECYCLE policies with
# inactivity rule conditions, not as a standalone `/api/v1/automations`
# resource. The SDK's `UserPolicyRuleCondition.inactivity` and
# `ScheduledUserLifecycleAction` models confirm this; the API rejects
# every other `type` candidate.
USER_LIFECYCLE_POLICY_TYPE = "USER_LIFECYCLE"

REQUIRED_SCOPES: dict[str, str] = {
    "automations": "okta.policies.read",
    "identity_providers": "okta.idps.read",
}


class User(OktaService):
    """Fetches Okta User Lifecycle Automations and external-directory IdPs.

    Populates:
    - `self.automations` — keyed by USER_LIFECYCLE policy rule id. Each
      entry projects the fields the 35-day inactivity check evaluates:
      identity (`id`, `name` — taken from the rule), `status`,
      `schedule_status` (inherited from the parent policy), the
      `inactivity_days` condition, the `lifecycle_action`, and the
      `applies_to_groups` derived from the rule's `people.groups.include`.
    - `self.external_directory_idps` — keyed by IdP id. Used to short
      circuit the STIG to N/A when user sourcing is delegated to an
      external directory (Active Directory, LDAP).

    The Okta Admin Console's "Workflow > Automations" page is rendered
    on top of `USER_LIFECYCLE` policies in the Management API
    (`list_policies(type='USER_LIFECYCLE')` + `list_policy_rules(...)`).
    There is no standalone `/api/v1/automations` GET endpoint; the SDK's
    `InactivityPolicyRuleCondition`, `UserPolicyRuleCondition`, and
    `ScheduledUserLifecycleAction` models all hang off the policy API.

    Required OAuth scopes (`REQUIRED_SCOPES`) are compared against the
    access token's granted scopes (`provider.identity.granted_scopes`).
    Missing scopes are recorded in `self.missing_scope` so the check
    can emit an explicit MANUAL finding.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }

        self.automations: dict[str, UserAutomation] = (
            {} if self.missing_scope["automations"] else self._list_automations()
        )
        self.external_directory_idps: dict[str, ExternalDirectoryIdp] = (
            {}
            if self.missing_scope["identity_providers"]
            else self._list_external_directory_idps()
        )

    def _list_automations(self) -> dict:
        logger.info("User - Listing USER_LIFECYCLE policies and rules...")
        try:
            return self._run(self._fetch_automations())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_automations(self) -> dict:
        result: dict[str, UserAutomation] = {}
        all_policies, err = await paginate(
            lambda after: self.client.list_policies(
                type=USER_LIFECYCLE_POLICY_TYPE, after=after
            )
        )
        if err is not None:
            logger.error(f"Error listing USER_LIFECYCLE policies: {err}")
            return result

        for policy in all_policies:
            policy_id = getattr(policy, "id", "") or ""
            if not policy_id:
                continue
            policy_status = _stringify_enum(getattr(policy, "status", None)) or ""
            policy_name = getattr(policy, "name", "") or ""
            rules = await self._fetch_rules(policy_id)
            for rule in rules:
                automation = _rule_to_automation(
                    rule, policy_id, policy_name, policy_status
                )
                if automation is None:
                    continue
                result[automation.id] = automation
        return result

    async def _fetch_rules(self, policy_id: str) -> list:
        rule_fetch_limit = 100
        result = await self.client.list_policy_rules(
            policy_id, limit=str(rule_fetch_limit)
        )
        err = result[-1]
        if err is not None:
            logger.error(
                f"Error listing rules for USER_LIFECYCLE policy {policy_id}: {err}"
            )
            return []
        rules = list(result[0] or [])
        if len(rules) >= rule_fetch_limit:
            logger.warning(
                f"USER_LIFECYCLE policy {policy_id} returned {len(rules)} rules — "
                f"the per-policy fetch limit ({rule_fetch_limit}) was hit; any "
                "rules beyond this limit are not evaluated."
            )
        return rules

    def _list_external_directory_idps(self) -> dict:
        logger.info("User - Listing Okta IdPs for external-directory detection...")
        try:
            return self._run(self._fetch_external_directory_idps())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_external_directory_idps(self) -> dict:
        result: dict[str, ExternalDirectoryIdp] = {}
        all_idps, err = await paginate(
            lambda after: self.client.list_identity_providers(after=after)
        )
        if err is not None:
            logger.error(f"Error listing identity providers: {err}")
            return result

        for idp in all_idps:
            idp_type = _stringify_enum(getattr(idp, "type", None)) or ""
            if idp_type.upper() not in EXTERNAL_DIRECTORY_IDP_TYPES:
                continue
            idp_status = _stringify_enum(getattr(idp, "status", None)) or ""
            if idp_status.upper() != "ACTIVE":
                continue
            idp_id = getattr(idp, "id", "") or ""
            if not idp_id:
                continue
            result[idp_id] = ExternalDirectoryIdp(
                id=idp_id,
                name=getattr(idp, "name", "") or "",
                type=idp_type,
                status=idp_status,
            )
        return result


def _rule_to_automation(
    rule, policy_id: str, policy_name: str, policy_status: str
) -> Optional["UserAutomation"]:
    """Project a USER_LIFECYCLE policy rule onto our automation snapshot."""
    rule_id = getattr(rule, "id", "") or ""
    if not rule_id:
        return None

    inactivity_days: Optional[int] = None
    applies_to_groups: list[str] = []
    conditions = getattr(rule, "conditions", None)
    people = getattr(conditions, "people", None) if conditions else None
    users = getattr(people, "users", None) if people else None
    inactivity = getattr(users, "inactivity", None) if users else None
    if inactivity is not None:
        number = getattr(inactivity, "number", None)
        unit = (_stringify_enum(getattr(inactivity, "unit", None)) or "").upper()
        if isinstance(number, int) and unit in {"DAYS", "DAY"}:
            inactivity_days = number
    groups = getattr(people, "groups", None) if people else None
    include_groups = getattr(groups, "include", None) if groups else None
    if include_groups:
        applies_to_groups = [str(g) for g in include_groups if g]

    actions = getattr(rule, "actions", None)
    user_lifecycle = (
        getattr(actions, "user_lifecycle", None) if actions else None
    ) or (getattr(actions, "userLifecycle", None) if actions else None)
    lifecycle_action: Optional[str] = None
    if user_lifecycle is not None:
        for attr in ("action", "status"):
            value = _stringify_enum(getattr(user_lifecycle, attr, None))
            if value:
                lifecycle_action = value.upper()
                break

    rule_name = getattr(rule, "name", "") or policy_name or "(unnamed)"
    rule_status = _stringify_enum(getattr(rule, "status", None)) or ""

    return UserAutomation(
        id=rule_id,
        name=rule_name,
        status=rule_status.upper(),
        schedule_status=policy_status.upper(),
        inactivity_days=inactivity_days,
        lifecycle_action=lifecycle_action,
        applies_to_groups=applies_to_groups,
        policy_id=policy_id,
        policy_name=policy_name,
    )


def _stringify_enum(value) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "value", None) or str(value)


class UserAutomation(BaseModel):
    id: str
    name: str = ""
    status: str = ""
    schedule_status: str = ""
    inactivity_days: Optional[int] = None
    lifecycle_action: Optional[str] = None
    applies_to_groups: list[str] = []
    policy_id: str = ""
    policy_name: str = ""


class ExternalDirectoryIdp(BaseModel):
    id: str
    name: str = ""
    type: str = ""
    status: str = ""
