from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_vulnerabilty_assessments_machines_on(Check):
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
                report.status_extended = f"Vulnerability assessment is set up in all VMs in subscription {subscription_name} ({subscription_id})."

                if (
                    assessments[
                        "Machines should have a vulnerability assessment solution"
                    ].status
                    == "Unhealthy"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Vulnerability assessment is not set up in all VMs in subscription {subscription_name} ({subscription_id})."

                findings.append(report)

        return findings
