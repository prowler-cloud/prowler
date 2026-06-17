from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_iot_hub_defender_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            iot_security_solutions,
        ) in defender_client.iot_security_solutions.items():
            subscription_name = defender_client.subscriptions.get(
                subscription_id, subscription_id
            )
            if not iot_security_solutions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.status = "FAIL"
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status_extended = f"No IoT Security Solutions found in the subscription {subscription_name} ({subscription_id})."
                findings.append(report)
            else:
                for iot_security_solution in iot_security_solutions.values():
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=iot_security_solution,
                    )
                    report.subscription = subscription_id
                    report.status = "PASS"
                    report.status_extended = f"The security solution {iot_security_solution.name} is enabled in subscription {subscription_name} ({subscription_id})."

                    if iot_security_solution.status != "Enabled":
                        report.status = "FAIL"
                        report.status_extended = f"The security solution {iot_security_solution.name} is disabled in subscription {subscription_name} ({subscription_id})"

                    findings.append(report)

        return findings
