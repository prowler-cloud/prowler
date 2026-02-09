from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_iot_hub_defender_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            iot_security_solutions,
        ) in defender_client.iot_security_solutions.items():
            if not iot_security_solutions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{defender_client.subscriptions[subscription_name]}"
                )
                report.status_extended = f"No IoT Security Solutions found in the subscription {subscription_name}."
                findings.append(report)
            else:
                for iot_security_solution in iot_security_solutions.values():
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=iot_security_solution,
                    )
                    report.subscription = subscription_name
                    report.status = "PASS"
                    report.status_extended = f"The security solution {iot_security_solution.name} is enabled in subscription {subscription_name}."

                    if iot_security_solution.status != "Enabled":
                        report.status = "FAIL"
                        report.status_extended = f"The security solution {iot_security_solution.name} is disabled in subscription {subscription_name}"

                    findings.append(report)

        return findings
