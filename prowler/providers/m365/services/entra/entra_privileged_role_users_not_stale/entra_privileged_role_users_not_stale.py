"""Check that users holding Tier 0 Microsoft Entra roles are not stale."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    PrivilegedUserSignInData,
    TIER_0_ROLE_NAMES,
)


class entra_privileged_role_users_not_stale(Check):
    """Ensure that users holding Tier 0 Microsoft Entra roles have signed in recently.

    This check identifies every user with an active or PIM-eligible Tier 0 role
    assignment and verifies that their last successful sign-in falls within a
    configurable threshold (default 90 days). Disabled accounts that still hold
    Tier 0 roles are flagged as stale regardless of their sign-in date.
    Emergency-access (break glass) accounts are excluded.

    - PASS: The privileged user signed in within the threshold, is a newly
      created account inside the grace period, or is an excluded emergency-
      access account.
    - FAIL: The privileged user is stale (last sign-in exceeds the threshold,
      never signed in outside the grace period, or the account is disabled
      while still holding a Tier 0 role).
    - MANUAL: Sign-in activity cannot be read (missing P1/P2 licence or
      permissions), or a per-user lookup failed.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the stale privileged user check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # ---- Gate: users could not be loaded ----
        if entra_client.users_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Privileged Users",
                resource_id="privilegedUsers",
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate stale privileged accounts: "
                f"{entra_client.users_error}."
            )
            findings.append(report)
            return findings

        # ---- Gate: sign-in activity tenant-level error (P1 missing) ----
        if entra_client.privileged_users_sign_in_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Privileged Users",
                resource_id="privilegedUsers",
            )
            report.status = "MANUAL"
            report.status_extended = f"{entra_client.privileged_users_sign_in_error}"
            findings.append(report)
            return findings

        # ---- No Tier 0 users at all ----
        if not entra_client.privileged_users_roles:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Privileged Users",
                resource_id="privilegedUsers",
            )
            report.status = "PASS"
            report.status_extended = "No users hold Tier 0 roles."
            findings.append(report)
            return findings

        # ---- Configuration ----
        threshold_days = entra_client.audit_config.get(
            "stale_privileged_account_days", 90
        )
        now = datetime.now(timezone.utc)
        threshold_date = now - timedelta(days=threshold_days)

        # ---- Identify break glass (emergency-access) accounts ----
        break_glass_ids = self._identify_break_glass_accounts()

        # ---- PIM eligible error suffix ----
        pim_suffix = ""
        if entra_client.pim_eligible_error:
            pim_suffix = (
                " Eligible (PIM) assignments could not be read and were "
                "not evaluated."
            )

        # ---- Evaluate each privileged user ----
        for user_id, assignments in entra_client.privileged_users_roles.items():
            user = entra_client.users.get(user_id)
            if not user:
                # User not in the directory listing - skip
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.id,
            )

            # Build human-readable role list
            role_descriptions = []
            for assignment in assignments:
                role_name = TIER_0_ROLE_NAMES.get(
                    assignment.role_template_id, assignment.role_template_id
                )
                role_descriptions.append(f"{role_name} ({assignment.assignment_type})")
            roles_str = ", ".join(role_descriptions)

            upn = user.user_principal_name or user.name

            # ---- Break glass exclusion ----
            if user_id in break_glass_ids:
                sign_in_data = entra_client.privileged_users_sign_in_data.get(user_id)
                last_activity = self._get_last_activity(sign_in_data)
                last_str = (
                    last_activity.strftime("%Y-%m-%d") if last_activity else "never"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"User '{user.name}' ({upn}) is excluded as an "
                    f"emergency-access account; last sign-in {last_str}."
                    f"{pim_suffix}"
                )
                findings.append(report)
                continue

            # ---- Per-user sign-in data error ----
            sign_in_data = entra_client.privileged_users_sign_in_data.get(user_id)
            if sign_in_data and sign_in_data.error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Sign-in activity for user '{user.name}' ({upn}) "
                    f"could not be retrieved: {sign_in_data.error}.{pim_suffix}"
                )
                findings.append(report)
                continue

            # ---- Disabled account with Tier 0 role ----
            if not user.account_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"User '{user.name}' ({upn}) is disabled but still holds "
                    f"Tier 0 role(s): {roles_str}.{pim_suffix}"
                )
                findings.append(report)
                continue

            # ---- Evaluate sign-in activity ----
            last_activity = self._get_last_activity(sign_in_data)

            if last_activity is not None:
                if last_activity >= threshold_date:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User '{user.name}' ({upn}) holds Tier 0 role(s) "
                        f"{roles_str} and last signed in successfully on "
                        f"{last_activity.strftime('%Y-%m-%d')} "
                        f"(threshold {threshold_days} days).{pim_suffix}"
                    )
                else:
                    days_ago = (now - last_activity).days
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User '{user.name}' ({upn}) holds Tier 0 role(s) "
                        f"{roles_str} and last signed in successfully on "
                        f"{last_activity.strftime('%Y-%m-%d')} "
                        f"({days_ago} days ago, threshold {threshold_days} "
                        f"days).{pim_suffix}"
                    )
            else:
                # Never signed in - check grace period
                created = user.created_date_time
                if created and created >= threshold_date:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User '{user.name}' ({upn}) holds Tier 0 role(s) "
                        f"{roles_str} and has never signed in, but the "
                        f"account was created on "
                        f"{created.strftime('%Y-%m-%d')} (within the "
                        f"{threshold_days}-day grace period).{pim_suffix}"
                    )
                else:
                    created_str = (
                        f"created {created.strftime('%Y-%m-%d')}"
                        if created
                        else "creation date unknown"
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User '{user.name}' ({upn}) holds Tier 0 role(s) "
                        f"{roles_str} and has never signed in "
                        f"({created_str}).{pim_suffix}"
                    )

            findings.append(report)

        return findings

    @staticmethod
    def _get_last_activity(
        sign_in_data: Optional[PrivilegedUserSignInData],
    ) -> Optional[datetime]:
        """Compute the effective last activity date from sign-in data.

        Prefers ``lastSuccessfulSignInDateTime``; falls back to the most
        recent of ``lastSignInDateTime`` and
        ``lastNonInteractiveSignInDateTime``.

        Args:
            sign_in_data: A ``PrivilegedUserSignInData`` instance or None.

        Returns:
            A timezone-aware ``datetime`` or ``None`` if no sign-in
            timestamps are available.
        """
        if not sign_in_data:
            return None
        if sign_in_data.last_successful_sign_in:
            return sign_in_data.last_successful_sign_in
        candidates = [
            ts
            for ts in (
                sign_in_data.last_sign_in,
                sign_in_data.last_non_interactive_sign_in,
            )
            if ts is not None
        ]
        return max(candidates) if candidates else None

    @staticmethod
    def _identify_break_glass_accounts() -> set[str]:
        """Identify emergency-access (break glass) accounts.

        Uses the same heuristic as
        ``entra_break_glass_account_fido2_security_key_registered``: a user
        excluded from every enabled Conditional Access policy is considered
        a break glass account.

        Returns:
            A set of user IDs identified as break glass accounts.
        """
        enabled_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state != ConditionalAccessPolicyState.DISABLED
        ]
        if not enabled_policies:
            return set()

        total_policy_count = len(enabled_policies)
        excluded_counter = Counter()
        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for user_id in user_conditions.excluded_users:
                    excluded_counter[user_id] += 1

        return {
            uid
            for uid, count in excluded_counter.items()
            if count == total_policy_count
        }
