from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.schema_client import schema_client


class eventbridge_schema_registry_cross_account_access(Check):
    def execute(self):
        findings = []
        for registry in schema_client.registries.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = registry.name
            report.resource_arn = registry.arn
            report.resource_tags = registry.tags
            report.region = registry.region
            report.status = "PASS"
            report.status_extended = f"EventBridge schema registry {registry.name} does not allow cross-account access."
            if registry.policy and "Statement" in registry.policy:
                cross_account_access = False
                if isinstance(registry.policy["Statement"], list):
                    for statement in registry.policy["Statement"]:
                        if not cross_account_access:
                            if (
                                statement["Effect"] == "Allow"
                                and "AWS" in statement["Principal"]
                            ):
                                if isinstance(statement["Principal"]["AWS"], list):
                                    for aws_account in statement["Principal"]["AWS"]:
                                        if (
                                            schema_client.audited_account
                                            not in aws_account
                                            or "*" == aws_account
                                        ):
                                            cross_account_access = True
                                            break
                                else:
                                    if (
                                        schema_client.audited_account
                                        not in statement["Principal"]["AWS"]
                                        or "*" == statement["Principal"]["AWS"]
                                    ):
                                        cross_account_access = True
                        else:
                            break
                else:
                    statement = registry.policy["Statement"]
                    if (
                        statement["Effect"] == "Allow"
                        and "AWS" in statement["Principal"]
                    ):
                        if isinstance(statement["Principal"]["AWS"], list):
                            for aws_account in statement["Principal"]["AWS"]:
                                if (
                                    schema_client.audited_account not in aws_account
                                    or "*" == aws_account
                                ):
                                    cross_account_access = True
                                    break
                        else:
                            if (
                                schema_client.audited_account
                                not in statement["Principal"]["AWS"]
                                or "*" == statement["Principal"]["AWS"]
                            ):
                                cross_account_access = True
                if cross_account_access:
                    report.status = "FAIL"
                    report.status_extended = f"EventBridge schema registry {registry.name} allows cross-account access."

            findings.append(report)

        return findings
