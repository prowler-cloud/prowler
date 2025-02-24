from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_admin_users_sign_in_frequency_enabled(Check):
    """Check if Conditional Access policies enforce sign-in frequency for admin users.

    This check ensures that administrators have a sign-in frequency policy enabled
    and that persistent browser session settings are correctly configured.
    """

    def execute(self) -> list[Check_Report_Microsoft365]:
        """Execute the check to validate sign-in frequency enforcement for admin users.

        Returns:
            list[Check_Report_Microsoft365]: A list containing the results of the check.
        """
        findings = []

        report = Check_Report_Microsoft365(
            metadata=self.metadata(),
            resource=entra_client.conditional_access_policies,
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access policy enforces sign-in frequency for admin users."
        )

        admin_role_ids = {
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
            "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
            "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        }

        for policy in entra_client.conditional_access_policies.values():
            if policy.state not in {
                ConditionalAccessPolicyState.ENABLED,
                ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            }:
                continue

            if not admin_role_ids.issuperset(
                policy.conditions.user_conditions.included_roles
            ):
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                policy.session_controls.sign_in_frequency.is_enabled
                and policy.session_controls.sign_in_frequency.frequency
                and policy.session_controls.sign_in_frequency.frequency <= 4
                and policy.session_controls.persistent_browser.is_enabled
                and policy.session_controls.persistent_browser.mode == "never"
            ):
                report.status = "PASS"
                report.status_extended = f"Conditional Access policy {policy.display_name} enforces sign-in frequency for admin users."
                break

        findings.append(report)

        return findings
