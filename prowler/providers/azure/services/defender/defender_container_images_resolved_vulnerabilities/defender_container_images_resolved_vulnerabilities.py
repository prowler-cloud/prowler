from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_container_images_resolved_vulnerabilities(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            assessments,
        ) in defender_client.assessments.items():
            if (
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                in assessments
                and getattr(
                    assessments[
                        "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                    ],
                    "status",
                    "NotApplicable",
                )
                != "NotApplicable"
            ):
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = assessments[
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
                report.resource_id = assessments[
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
                report.status_extended = f"Azure running container images do not have unresolved vulnerabilities in subscription '{subscription_name}'."

                if (
                    assessments[
                        "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Azure running container images have unresolved vulnerabilities in subscription '{subscription_name}'."

                findings.append(report)

        return findings
