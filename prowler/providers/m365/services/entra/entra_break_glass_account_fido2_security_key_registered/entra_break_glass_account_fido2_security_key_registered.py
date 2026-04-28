from collections import Counter

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_break_glass_account_fido2_security_key_registered(Check):
    """Ensure that break glass accounts have FIDO2 security keys registered.

    This check identifies break glass (emergency access) accounts by finding users
    excluded from all enabled Conditional Access policies, then verifies each has
    at least one FIDO2 security key registered as an authentication method.

    - PASS: The break glass account has a FIDO2 security key (fido2SecurityKey) registered.
    - MANUAL: The account has a device-bound passkey but it cannot be confirmed as FIDO2,
              or no break glass accounts could be identified.
    - FAIL: The break glass account does not have a FIDO2 security key registered.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for FIDO2 registration on break glass accounts.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        enabled_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state != ConditionalAccessPolicyState.DISABLED
        ]

        if not enabled_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Break Glass Accounts",
                resource_id="breakGlassAccounts",
            )
            report.status = "MANUAL"
            report.status_extended = "No enabled Conditional Access policies found. Break glass accounts cannot be identified to verify FIDO2 registration."
            findings.append(report)
            return findings

        total_policy_count = len(enabled_policies)

        excluded_users_counter = Counter()
        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for user_id in user_conditions.excluded_users:
                    excluded_users_counter[user_id] += 1

        break_glass_user_ids = [
            user_id
            for user_id, count in excluded_users_counter.items()
            if count == total_policy_count
        ]

        if not break_glass_user_ids:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Break Glass Accounts",
                resource_id="breakGlassAccounts",
            )
            report.status = "MANUAL"
            report.status_extended = "No break glass accounts identified. No users are excluded from all enabled Conditional Access policies."
            findings.append(report)
            return findings

        # Check if there was an error retrieving user registration details
        if entra_client.user_registration_details_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Break Glass Accounts",
                resource_id="breakGlassAccounts",
            )
            report.status = "FAIL"
            report.status_extended = f"Cannot verify FIDO2 security key registration for break glass accounts: {entra_client.user_registration_details_error}."
            findings.append(report)
            return findings

        for user_id in break_glass_user_ids:
            user = entra_client.users.get(user_id)
            if not user:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.id,
            )

            auth_methods = set(user.authentication_methods)
            has_fido2 = "fido2SecurityKey" in auth_methods
            has_passkey_device_bound = "passKeyDeviceBound" in auth_methods

            if has_fido2:
                report.status = "PASS"
                report.status_extended = f"Break glass account {user.name} has a FIDO2 security key registered."
            elif has_passkey_device_bound:
                report.status = "MANUAL"
                report.status_extended = f"Break glass account {user.name} has a device-bound passkey registered, but it cannot be confirmed whether it is a FIDO2 security key."
            else:
                report.status = "FAIL"
                report.status_extended = f"Break glass account {user.name} does not have a FIDO2 security key registered."

            findings.append(report)

        return findings
