from typing import Optional

from pydantic import BaseModel, ValidationError

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate
from prowler.providers.okta.lib.service.raw_fetch import (
    get_json_paginated as raw_get_json_paginated,
)
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
        try:
            all_policies, err = await paginate(
                lambda after: self.client.list_policies(
                    type=USER_LIFECYCLE_POLICY_TYPE, after=after
                )
            )
        except (ValueError, ValidationError) as ex:
            # Upstream okta-sdk-python bug: `Policy.from_dict` uses a
            # discriminator dispatch that maps `type` → concrete Policy
            # subclass, and `USER_LIFECYCLE` is not in the map. The SDK
            # raises ValueError ("failed to lookup discriminator value")
            # even though the API returns a valid policy. Fall back to
            # raw JSON. Remove once okta-sdk-python adds
            # USER_LIFECYCLE → UserLifecyclePolicy to the mapping.
            logger.warning(
                f"Okta SDK raised {type(ex).__name__} parsing USER_LIFECYCLE "
                "policies — falling back to raw-JSON parse. This is an "
                "okta-sdk-python deserialization bug "
                "(missing discriminator mapping)."
            )
            return await self._fetch_automations_raw()

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
            if rules is None:
                # Rule typed parsing tripped an SDK validator. Re-run the
                # whole automation discovery via raw JSON so we don't lose
                # the rule data for this — or any other — policy. Cheaper
                # than mixing typed and raw projections.
                logger.warning(
                    f"Rule typed parsing failed for USER_LIFECYCLE policy "
                    f"{policy_id} — re-running all automations via raw-JSON."
                )
                return await self._fetch_automations_raw()
            if not rules:
                # A policy with no rules exists in the Admin Console UI as
                # an "Automation" the operator hasn't finished configuring
                # (no conditions, no actions). Emit a placeholder so the
                # check FAILs with a specific message naming every missing
                # piece, instead of pretending the policy doesn't exist.
                result[policy_id] = _shell_automation(
                    policy_id, policy_name, policy_status
                )
                continue
            for rule in rules:
                automation = _rule_to_automation(rule, policy)
                if automation is None:
                    continue
                result[automation.id] = automation
        return result

    async def _fetch_rules(self, policy_id: str) -> Optional[list]:
        """Return the policy's typed rules, or None to signal raw fallback.

        The Okta SDK's `list_policy_rules` shares the same brittle typed
        deserialization as `list_policies` (strict pydantic validators
        rejecting values the API actually returns). When that happens the
        caller can't reuse any of the typed projection for this policy —
        we return None as a sentinel and the caller re-runs the whole
        discovery via `_fetch_automations_raw`. Returning `[]` would
        otherwise misclassify the policy as an "unfinished automation"
        and FAIL it.
        """
        rule_fetch_limit = 100
        try:
            result = await self.client.list_policy_rules(
                policy_id, limit=str(rule_fetch_limit)
            )
        except (ValueError, ValidationError) as ex:
            logger.warning(
                f"Okta SDK raised {type(ex).__name__} parsing rules for "
                f"USER_LIFECYCLE policy {policy_id} — signaling raw fallback."
            )
            return None
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

    async def _fetch_automations_raw(self) -> dict:
        """Raw-JSON fallback for `list_policies(type='USER_LIFECYCLE')`.

        Bypasses the SDK's typed deserialization via the shared
        `get_json_paginated` helper, then drains each policy's rules
        via the same path. Projects everything onto our `UserAutomation`
        snapshot which only validates the fields the check reads.
        """
        result: dict[str, UserAutomation] = {}
        policies_data = await raw_get_json_paginated(
            self.client,
            f"/api/v1/policies?type={USER_LIFECYCLE_POLICY_TYPE}",
            page_size=200,
            context="USER_LIFECYCLE policies",
        )
        if policies_data is None:
            return result

        for policy_dict in policies_data:
            if not isinstance(policy_dict, dict):
                continue
            policy_id = policy_dict.get("id")
            if not policy_id:
                continue
            policy_status = (policy_dict.get("status") or "").upper()
            policy_name = policy_dict.get("name") or ""

            rules_data = await raw_get_json_paginated(
                self.client,
                f"/api/v1/policies/{policy_id}/rules",
                page_size=100,
                context=f"USER_LIFECYCLE policy {policy_id} rules",
            )
            if not rules_data:
                # No rules under the policy → emit placeholder. Same
                # rationale as the typed path: surface the unfinished
                # automation so the check can name what's missing.
                result[policy_id] = _shell_automation(
                    policy_id, policy_name, policy_status
                )
                continue
            for rule_dict in rules_data:
                automation = _raw_rule_to_automation(
                    rule_dict, policy_dict, policy_id, policy_name, policy_status
                )
                if automation is None:
                    continue
                result[automation.id] = automation
        return result

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


def _rule_to_automation(rule, policy) -> Optional["UserAutomation"]:
    """Project a typed USER_LIFECYCLE policy + rule pair onto our snapshot.

    Important: in the actual API response, an Okta "Automation" is split
    across two resources — the **inactivity condition + group scope**
    live on the *policy* (`policy.conditions.people.users.inactivity`,
    `policy.conditions.people.groups.include`), and the **lifecycle
    action** lives on the *rule* (`rule.actions.user_lifecycle.action`
    on the typed model; `updateUserLifecycle.targetStatus` on raw JSON).
    The rule's own `conditions` is typically empty. Projecting requires
    both — kept aligned with `_raw_rule_to_automation` so the two paths
    yield identical snapshots.
    """
    rule_id = getattr(rule, "id", "") or ""
    if not rule_id:
        return None

    policy_id = getattr(policy, "id", "") or ""
    policy_name = getattr(policy, "name", "") or ""
    policy_status = (_stringify_enum(getattr(policy, "status", None)) or "").upper()

    # Inactivity + groups live on the POLICY in the API response.
    inactivity_days: Optional[int] = None
    applies_to_groups: list[str] = []
    conditions = getattr(policy, "conditions", None)
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

    # Lifecycle action lives on the RULE.
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
        schedule_status=policy_status,
        inactivity_days=inactivity_days,
        lifecycle_action=lifecycle_action,
        applies_to_groups=applies_to_groups,
        policy_id=policy_id,
        policy_name=policy_name,
    )


def _raw_rule_to_automation(
    rule_dict,
    policy_dict,
    policy_id: str,
    policy_name: str,
    policy_status: str,
) -> Optional["UserAutomation"]:
    """Project a raw USER_LIFECYCLE policy+rule pair onto our snapshot.

    Important: in the actual API response, an Okta "Automation" is split
    across two resources — the **inactivity condition + group scope**
    live on the *policy* (`policy.conditions.people.users.inactivity`,
    `policy.conditions.people.groups.include`), and the **lifecycle
    action** lives on the *rule*
    (`rule.actions.updateUserLifecycle.targetStatus`). The rule's own
    `conditions` is typically empty `{}`. Projecting requires both.

    Schedule isn't exposed by the API on either resource. Okta runs an
    automation on its UI-configured schedule iff the policy is ACTIVE,
    so we treat `policy.status` as the schedule proxy.
    """
    if not isinstance(rule_dict, dict):
        return None
    rule_id = rule_dict.get("id")
    if not rule_id:
        return None

    # Inactivity + groups live on the POLICY in the API response.
    inactivity_days: Optional[int] = None
    applies_to_groups: list[str] = []
    if isinstance(policy_dict, dict):
        policy_conditions = policy_dict.get("conditions") or {}
        people = policy_conditions.get("people") or {}
        users = people.get("users") or {}
        inactivity = users.get("inactivity")
        if isinstance(inactivity, dict):
            number = inactivity.get("number")
            unit = (inactivity.get("unit") or "").upper()
            if isinstance(number, int) and unit in {"DAYS", "DAY"}:
                inactivity_days = number
        groups = people.get("groups") or {}
        include_groups = groups.get("include")
        if isinstance(include_groups, list):
            applies_to_groups = [str(g) for g in include_groups if g]

    # Lifecycle action lives on the RULE under
    # `actions.updateUserLifecycle.targetStatus` (the API uses
    # "updateUserLifecycle" rather than the SDK's `user_lifecycle`).
    rule_actions = rule_dict.get("actions") or {}
    update_user_lifecycle = rule_actions.get("updateUserLifecycle") or {}
    lifecycle_action: Optional[str] = None
    if isinstance(update_user_lifecycle, dict):
        target = update_user_lifecycle.get("targetStatus")
        if isinstance(target, str) and target:
            lifecycle_action = target.upper()

    return UserAutomation(
        id=rule_id,
        name=(rule_dict.get("name") or policy_name or "(unnamed)"),
        status=(rule_dict.get("status") or "").upper(),
        schedule_status=policy_status,
        inactivity_days=inactivity_days,
        lifecycle_action=lifecycle_action,
        applies_to_groups=applies_to_groups,
        policy_id=policy_id,
        policy_name=policy_name,
    )


def _shell_automation(
    policy_id: str, policy_name: str, policy_status: str
) -> "UserAutomation":
    """Placeholder UserAutomation for a USER_LIFECYCLE policy with no rules.

    Surfaces the unfinished automation in `self.automations` so the check
    can list every missing piece in its FAIL message (no inactivity
    condition, no lifecycle action, status inactive, etc.) instead of
    silently dropping the policy.
    """
    upper_status = (policy_status or "").upper()
    return UserAutomation(
        id=policy_id,
        name=policy_name or "(unnamed automation)",
        status=upper_status,
        schedule_status=upper_status,
        inactivity_days=None,
        lifecycle_action=None,
        applies_to_groups=[],
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
