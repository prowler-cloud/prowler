from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_system_updates_are_applied(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():
            if (
                "Log Analytics agent should be installed on virtual machines"
                in assessments
                and "Machines should be configured to periodically check for missing system updates"
                in assessments
                and "System updates should be installed on your machines" in assessments
            ):
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = assessments[
                    "System updates should be installed on your machines"
                ].resource_name
                report.resource_id = assessments[
                    "System updates should be installed on your machines"
                ].resource_id
                report.status_extended = f"System updates are applied for all the VMs in the subscription {subscription_name}."

                if (
                    assessments[
                        "Log Analytics agent should be installed on virtual machines"
                    ].status
                    == "Unhealthy"
                    or assessments[
                        "Machines should be configured to periodically check for missing system updates"
                    ].status
                    == "Unhealthy"
                    or assessments[
                        "System updates should be installed on your machines"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"System updates are not applied for all the VMs in the subscription {subscription_name}."

                findings.append(report)

        return findings
