import importlib
from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

exchange_client = importlib.import_module(
    "prowler.providers.m365.services.exchange.exchange_client"
).exchange_client


class exchange_application_access_policy_restricts_mailbox_apps(Check):
    """
    Check if applications with Exchange mailbox permissions
    are restricted using Exchange Application Access Policies.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []

        application_access_policies = exchange_client.application_access_policies
        if application_access_policies is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=exchange_client.organization_config,
                resource_name="Exchange Online",
                resource_id="ExchangeOnlineTenant",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Exchange Online PowerShell is unavailable. "
                "Enable Exchange Online PowerShell credentials to evaluate "
                "Application Access Policies."
            )
            findings.append(report)
            return findings

        mailbox_permission_collection_error = getattr(
            entra_client,
            "exchange_mailbox_permission_service_principals_error",
            None,
        )
        if isinstance(mailbox_permission_collection_error, str):
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=exchange_client.organization_config,
                resource_name="Exchange Online",
                resource_id="ExchangeOnlineTenant",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Microsoft Graph mailbox permission collection failed. "
                "Manually verify whether applications with Exchange mailbox "
                "permissions are restricted using Application Access Policies."
            )
            findings.append(report)
            return findings

        policy_app_ids = {
            policy.app_id.lower()
            for policy in application_access_policies
            if getattr(policy, "app_id", None)
            and getattr(policy, "access_right", None) == "RestrictAccess"
        }

        service_principals = (
            entra_client.exchange_mailbox_permission_service_principals.values()
        )
        for service_principal in service_principals:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=service_principal,
                resource_name=service_principal.name,
                resource_id=service_principal.id,
            )
            permissions = ", ".join(service_principal.exchange_mailbox_permissions)

            if service_principal.app_id.lower() in policy_app_ids:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{service_principal.name}' "
                    f"({service_principal.app_id}) "
                    "has Exchange mailbox permissions "
                    f"({permissions}) and is restricted using an Application "
                    "Access Policy."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal '{service_principal.name}' "
                    f"({service_principal.app_id}) "
                    "has Exchange mailbox permissions "
                    f"({permissions}) but is not restricted using an Application "
                    "Access Policy."
                )

            findings.append(report)

        return findings
