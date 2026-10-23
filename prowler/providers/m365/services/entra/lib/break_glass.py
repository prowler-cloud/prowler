"""Shared helper for identifying break-glass (emergency access) accounts.

Break-glass accounts are identified as users excluded from **every** enabled
Conditional Access policy.  This heuristic is the same one used by
``entra_break_glass_account_fido2_security_key_registered`` and
``entra_emergency_access_exclusion``.  The helper centralises the logic so
that new checks (e.g. PIM standing-assignment checks) do not need to
duplicate it.
"""

from collections import Counter
from typing import Dict, List, Optional, Set

from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
)


def identify_break_glass_user_ids(
    conditional_access_policies: Dict[str, ConditionalAccessPolicy],
    configured_emergency_user_ids: Optional[List[str]] = None,
) -> Optional[Set[str]]:
    """Return the set of user IDs considered emergency-access (break-glass).

    The heuristic identifies users excluded from **every** enabled Conditional
    Access policy.  The result is merged with any explicitly configured
    emergency-access user IDs provided via ``configured_emergency_user_ids``.

    Args:
        conditional_access_policies: The tenant's Conditional Access policies,
            keyed by policy ID.  When the dict is empty the heuristic cannot
            identify any accounts and returns an empty set (an empty set is a
            valid result — it means the tenant has no CA policies or no user is
            universally excluded).
        configured_emergency_user_ids: Optional list of user object IDs
            explicitly designated as emergency-access accounts in the Prowler
            configuration.

    Returns:
        A set of user object IDs considered break-glass accounts, or ``None``
        when Conditional Access policies are unavailable (the caller passed
        ``None``) and therefore the heuristic cannot run.
    """
    explicit_ids = set(configured_emergency_user_ids or [])

    if conditional_access_policies is None:
        # CA policies unavailable — cannot run the heuristic.
        return None

    enabled_policies = [
        policy
        for policy in conditional_access_policies.values()
        if policy.state != ConditionalAccessPolicyState.DISABLED
    ]

    if not enabled_policies:
        # No enabled policies → heuristic returns nothing; merge explicit IDs.
        return explicit_ids

    total_policy_count = len(enabled_policies)

    excluded_counter: Counter = Counter()
    for policy in enabled_policies:
        user_conditions = policy.conditions.user_conditions
        if user_conditions:
            for user_id in user_conditions.excluded_users:
                excluded_counter[user_id] += 1

    heuristic_ids = {
        user_id
        for user_id, count in excluded_counter.items()
        if count == total_policy_count
    }

    return heuristic_ids | explicit_ids
