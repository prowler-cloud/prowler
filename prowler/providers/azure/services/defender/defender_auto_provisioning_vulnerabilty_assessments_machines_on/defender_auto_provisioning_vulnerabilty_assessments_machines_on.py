from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_vulnerabilty_assessments_machines_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            assessments,
        ) in defender_client.assessments.items():
            if (
                "Machines should have a vulnerability assessment solution"
                in assessments
            ):
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=assessments[
                        "Machines should have a vulnerability assessment solution"
                    ],
                )
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Vulnerability assessment is set up in all VMs in subscription {subscription_id}."

                if (
                    assessments[
                        "Machines should have a vulnerability assessment solution"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Vulnerability assessment is not set up in all VMs in subscription {subscription_id}."

                findings.append(report)

        return findings
