from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_vulnerabilty_assessments_machines_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():
            if (
                "Machines should have a vulnerability assessment solution"
                in assessments
            ):
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = assessments[
                    "Machines should have a vulnerability assessment solution"
                ].resource_name
                report.resource_id = assessments[
                    "Machines should have a vulnerability assessment solution"
                ].resource_id
                report.status_extended = f"Vulnerability assessment is set up in all VMs in subscription {subscription_name}."

                if (
                    assessments[
                        "Machines should have a vulnerability assessment solution"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Vulnerability assessment is not set up in all VMs in subscription {subscription_name}."

                findings.append(report)

        return findings
