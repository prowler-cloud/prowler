"""Check that the krbtgt_AzureAD account is not synchronized to Entra ID.

Port of Maester test MT.1147.  The on-premises krbtgt_AzureAD account (created
by ``Set-AzureADKerberosServer``) must not be synced to Entra ID because it
holds the keys used to issue partial Kerberos TGTs.  Syncing it widens the
attack surface between AD and Entra ID trust boundaries.
"""

import re
from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import User

# Name constant and compiled regex used for matching – identical to Maester.
_KRBTGT_NAME = "krbtgt_azuread"
_DN_REGEX = re.compile(r"(?i)(^|,)CN=krbtgt_AzureAD,")


def _is_krbtgt_azuread(user: User) -> str | None:
    """Return the matched attribute name if the user is the krbtgt_AzureAD account.

    All comparisons are case-insensitive, matching Maester MT.1147 logic.

    Args:
        user: An ``entra_service.User`` instance.

    Returns:
        The name of the first attribute that matched (e.g. ``"displayName"``),
        or ``None`` when the user does not match.
    """
    if user.name and user.name.casefold() == _KRBTGT_NAME:
        return "displayName"

    if user.mail_nickname and user.mail_nickname.casefold() == _KRBTGT_NAME:
        return "mailNickname"

    if (
        user.on_premises_sam_account_name
        and user.on_premises_sam_account_name.casefold() == _KRBTGT_NAME
    ):
        return "onPremisesSamAccountName"

    if user.user_principal_name:
        upn_prefix = user.user_principal_name.split("@")[0]
        if upn_prefix.casefold() == _KRBTGT_NAME:
            return "userPrincipalName"

    if user.on_premises_distinguished_name and _DN_REGEX.search(
        user.on_premises_distinguished_name
    ):
        return "onPremisesDistinguishedName"

    return None


class entra_directory_sync_krbtgt_azuread_not_synced(Check):
    """Ensure the krbtgt_AzureAD account is not synchronized from on-premises AD.

    The Microsoft Entra Kerberos server's krbtgt account (krbtgt_AzureAD) must
    remain on-premises only.  Synchronizing it to Entra ID creates a privilege-
    escalation path between the on-premises AD and cloud trust boundaries.

    - PASS: The tenant is cloud-only, or no synchronized user matches
      krbtgt_AzureAD.
    - FAIL: A synchronized user matching krbtgt_AzureAD is found.
    - MANUAL: Users could not be read or organizations are unavailable.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings: List[CheckReportM365] = []

        organizations = entra_client.organizations or []

        # --- Edge case: organizations unavailable ---
        if not organizations:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_id="entra_directory_sync",
                resource_name="Entra Directory Sync",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot determine whether on-premises synchronization is "
                "enabled; verify that Directory.Read.All is granted."
            )
            findings.append(report)
            return findings

        on_premises_sync_enabled = any(
            org.on_premises_sync_enabled for org in organizations
        )

        # --- Cloud-only tenant: PASS per organization ---
        if not on_premises_sync_enabled:
            for org in organizations:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=org,
                    resource_id=org.id,
                    resource_name=org.name,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Entra organization {org.name} is cloud-only "
                    "(no on-premises sync); krbtgt_AzureAD synchronization "
                    "is not applicable."
                )
                findings.append(report)
            return findings

        # --- Hybrid tenant: check if users could be read ---
        if entra_client.users_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_id="entra_directory_sync",
                resource_name="Entra Directory Sync",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate krbtgt_AzureAD synchronization: "
                f"{entra_client.users_error}."
            )
            findings.append(report)
            return findings

        # --- Hybrid tenant: evaluate synced users ---
        matched_any = False
        for user in entra_client.users.values():
            if not user.on_premises_sync_enabled:
                continue

            matched_attr = _is_krbtgt_azuread(user)
            if matched_attr is None:
                continue

            matched_any = True

            # Build descriptive status_extended with available attributes.
            parts = [f"'{user.name}'"]
            if user.user_principal_name:
                parts.append(user.user_principal_name)
            if user.on_premises_distinguished_name:
                parts.append(user.on_premises_distinguished_name)

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_id=user.id,
                resource_name=user.name,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Synchronized user {', '.join(parts)} is the Microsoft "
                "Entra Kerberos krbtgt account synchronized from "
                f"on-premises AD (matched on {matched_attr})."
            )
            findings.append(report)

        # No matching user found in a hybrid tenant: PASS per organization.
        if not matched_any:
            for org in organizations:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=org,
                    resource_id=org.id,
                    resource_name=org.name,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Entra organization {org.name} does not have the "
                    "krbtgt_AzureAD account synchronized from on-premises AD."
                )
                findings.append(report)

        return findings
