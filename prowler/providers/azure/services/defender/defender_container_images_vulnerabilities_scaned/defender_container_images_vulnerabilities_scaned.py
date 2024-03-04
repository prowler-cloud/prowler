from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_container_images_vulnerabilities_scaned(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.resource_id = "Microsoft.Security/assessments"
            report.resource_name = "Microsoft.Security/assessments"
            report.subscription = subscription_name
            report.status_extended = f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is not enabled in subscription {subscription_name}."
            if (
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                in assessments
            ):
                report.resource_name = assessments[
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
                report.resource_id = assessments[
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
                report.status_extended = f"Endpoint protection is set up in all VMs in subscription {subscription_name}."

                if (
                    assessments[
                        "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                    ].status
                    != "Unhealthy"
                ):
                    report.status = "PASS"
                    report.status_extended = f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is enabled in subscription {subscription_name}."

                findings.append(report)

        return findings
