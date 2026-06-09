from typing import List

from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import (
    exchange_client,
)


class exchange_application_access_policy_restricts_mailbox_apps(Check):
    """
    Check if applications with Exchange mailbox permissions
    are restricted using Exchange Application Access Policies.
    """

    REQUIRED_GRAPH_PERMISSIONS = {
        "Mail.Read",
        "Mail.ReadWrite",
        "Mail.Send",
        "MailboxSettings.Read",
        "MailboxSettings.ReadWrite",
        "full_access_as_app",
    }

    MICROSOFT_FIRST_PARTY_APP_IDS = {
        "00000003-0000-0000-c000-000000000000",
    }

    def execute(self) -> List[CheckReportM365]:
        findings = []

        organization_config = exchange_client.organization_config

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=organization_config,
            resource_name="Exchange Online",
            resource_id="ExchangeOnlineTenant",
        )

        # Exchange Online PowerShell unavailable
        if not hasattr(exchange_client, "application_access_policies"):
            report.status = "MANUAL"
            report.status_extended = (
                "Exchange Online PowerShell is unavailable. "
                "Unable to evaluate Application Access Policies."
            )

            findings.append(report)
            return findings

        application_access_policies = exchange_client.application_access_policies

        policy_app_ids = {
            policy.app_id
            for policy in application_access_policies
            if hasattr(policy, "app_id")
        }

        offending_apps = []
        oauth_apps = entra_client.oauth_apps or {}

        for app in oauth_apps.values():
            if app.id in self.MICROSOFT_FIRST_PARTY_APP_IDS:
                continue

            exchange_permissions = []

            for permission in app.permissions:
                if (
                    permission.permission_type.lower() == "application"
                    and permission.name in self.REQUIRED_GRAPH_PERMISSIONS
                ):
                    exchange_permissions.append(permission.name)

            if not exchange_permissions:
                continue

            if app.id not in policy_app_ids:
                offending_apps.append(
                    {
                        "display_name": app.name,
                        "app_id": app.id,
                        "permissions": exchange_permissions,
                    }
                )

        if offending_apps:
            report.status = "FAIL"

            failed_apps = []

            for app in offending_apps:
                failed_apps.append(f"{app['display_name']} ({app['app_id']})")

            report.status_extended = (
                "The following applications have Exchange mailbox "
                "permissions but are not restricted using "
                "Application Access Policies: " + ", ".join(failed_apps)
            )

        else:
            report.status = "PASS"
            report.status_extended = (
                "All applications with Exchange mailbox permissions "
                "are restricted using Application Access Policies."
            )

        findings.append(report)

        return findings
