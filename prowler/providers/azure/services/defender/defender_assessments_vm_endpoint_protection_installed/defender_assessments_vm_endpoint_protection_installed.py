from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_assessments_vm_endpoint_protection_installed(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():

            if (
                "Install endpoint protection solution on virtual machines"
                in assessments
            ):
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = assessments[
                    "Install endpoint protection solution on virtual machines"
                ].resource_name
                report.resource_id = assessments[
                    "Install endpoint protection solution on virtual machines"
                ].resource_id
                report.status_extended = f"Endpoint protection is set up in all VMs in subscription {subscription_name}."

                if (
                    assessments[
                        "Install endpoint protection solution on virtual machines"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Endpoint protection is not set up in all VMs in subscription {subscription_name}."

                findings.append(report)

        return findings
