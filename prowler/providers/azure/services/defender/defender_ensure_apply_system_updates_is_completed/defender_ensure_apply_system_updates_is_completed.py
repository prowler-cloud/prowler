from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_apply_system_updates_is_completed(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():

            if (
                "Machines should be configured to periodically check for missing system updates"
                in assessments
                and "System updates should be installed on your machines" in assessments
            ):
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = assessments[
                    "Machines should be configured to periodically check for missing system updates"
                ].resource_name
                report.resource_id = assessments[
                    "Machines should be configured to periodically check for missing system updates"
                ].resource_id
                report.status_extended = f"Apply system updates assessment is HEALTHY for subscription {subscription_name}."

                if (
                    assessments[
                        "Machines should be configured to periodically check for missing system updates"
                    ].status
                    != "Healthy"
                    or assessments[
                        "System updates should be installed on your machines"
                    ].status
                    != "Healthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Apply system updates assessment is UNHEALTHY for subscription {subscription_name}."

                findings.append(report)

        return findings
