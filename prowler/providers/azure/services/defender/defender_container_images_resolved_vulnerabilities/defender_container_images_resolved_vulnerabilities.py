from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_container_images_resolved_vulnerabilities(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        if defender_client.resource_groups:
            for subscription in defender_client.subscriptions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription}': this check is subscription-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings

        for (
            subscription_id,
            assessments,
        ) in defender_client.assessments.items():
            subscription_name = defender_client.subscriptions.get(
                subscription_id, subscription_id
            )
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
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=assessments[
                        "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                    ],
                )
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Azure running container images do not have unresolved vulnerabilities in subscription '{subscription_name} ({subscription_id})'."
                if (
                    assessments[
                        "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Azure running container images have unresolved vulnerabilities in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
