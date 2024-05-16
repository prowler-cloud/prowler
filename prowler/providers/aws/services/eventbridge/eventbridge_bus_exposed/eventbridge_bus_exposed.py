from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.eventbridge_client import (
    eventbridge_client,
)


class eventbridge_bus_exposed(Check):
    def execute(self):
        findings = []
        for bus in eventbridge_client.buses.values():
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = (
                f"EventBridge event bus {bus.name} is not exposed to everyone."
            )
            report.resource_id = bus.name
            report.resource_arn = bus.arn
            report.resource_tags = bus.tags
            report.region = bus.region
            # If the "Principal" element value is set to { "AWS": "*" } and the policy statement is not using any Condition clauses to filter the access, the selected AWS EventBridge bus is publicly accessible.
            if bus.policy and "Statement" in bus.policy:
                for statement in bus.policy["Statement"]:
                    if (
                        "Principal" in statement
                        and (
                            "*" == statement["Principal"]
                            or "arn:aws:iam::*:root" in statement["Principal"]
                        )
                        and "Condition" not in statement
                    ):
                        report.status = "FAIL"
                        report.status_extended = (
                            f"EventBridge event bus {bus.name} is exposed to everyone."
                        )
                    elif "Principal" in statement and "AWS" in statement["Principal"]:
                        if isinstance(statement["Principal"]["AWS"], str):
                            principals = [statement["Principal"]["AWS"]]
                        else:
                            principals = statement["Principal"]["AWS"]
                        for principal_arn in principals:
                            if (
                                principal_arn == "*"
                                or principal_arn == "arn:aws:iam::*:root"
                            ) and "Condition" not in statement:
                                report.status = "FAIL"
                                report.status_extended = f"EventBridge event bus {bus.name} is exposed to everyone."
            findings.append(report)
        return findings
