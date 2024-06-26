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
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = "IoT Hub Defender"
                report.resource_id = "IoT Hub Defender"
                report.status_extended = f"No IoT Security Solutions found in the subscription {subscription_name}."
                findings.append(report)
                continue

            for (
                iot_security_solution_name,
                iot_security_solution,
            ) in iot_security_solutions.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = iot_security_solution_name
                report.resource_id = iot_security_solution.resource_id
                report.status_extended = f"The security solution {iot_security_solution_name} is enabled in susbscription {subscription_name}."

                if iot_security_solution.status != "Enabled":
                    report.status = "FAIL"
                    report.status_extended = f"The security solution {iot_security_solution_name} is disabled in susbscription {subscription_name}"

                findings.append(report)

        return findings
