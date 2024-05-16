from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.eventbridge_client import (
    eventbridge_client,
)


class eventbridge_bus_cross_account_access(Check):
    def execute(self):
        findings = []
        for bus in eventbridge_client.buses.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = bus.name
            report.resource_arn = bus.arn
            report.resource_tags = bus.tags
            report.region = bus.region
            report.status = "PASS"
            report.status_extended = (
                f"EventBridge event bus {bus.name} does not allow cross-account access."
            )
            if bus.policy and "Statement" in bus.policy:
                cross_account_access = False
                if isinstance(bus.policy["Statement"], list):
                    for statement in bus.policy["Statement"]:
                        if not cross_account_access:
                            if (
                                statement["Effect"] == "Allow"
                                and "AWS" in statement["Principal"]
                            ):
                                if isinstance(statement["Principal"]["AWS"], list):
                                    for aws_account in statement["Principal"]["AWS"]:
                                        if (
                                            eventbridge_client.audited_account
                                            not in aws_account
                                            or "*" == aws_account
                                        ):
                                            cross_account_access = True
                                            break
                                else:
                                    if (
                                        eventbridge_client.audited_account
                                        not in statement["Principal"]["AWS"]
                                        or "*" == statement["Principal"]["AWS"]
                                    ):
                                        cross_account_access = True
                        else:
                            break
                else:
                    statement = bus.policy["Statement"]
                    if (
                        statement["Effect"] == "Allow"
                        and "AWS" in statement["Principal"]
                    ):
                        if isinstance(statement["Principal"]["AWS"], list):
                            for aws_account in statement["Principal"]["AWS"]:
                                if (
                                    eventbridge_client.audited_account
                                    not in aws_account
                                    or "*" == aws_account
                                ):
                                    cross_account_access = True
                                    break
                        else:
                            if (
                                eventbridge_client.audited_account
                                not in statement["Principal"]["AWS"]
                                or "*" == statement["Principal"]["AWS"]
                            ):
                                cross_account_access = True
                if cross_account_access:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"EventBridge event bus {bus.name} allows cross-account access."
                    )

            findings.append(report)

        return findings
