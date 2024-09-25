from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_autoscaling_enabled(Check):
    def execute(self):
        findings = []
        for table_arn, table in dynamodb_client.tables.items():
            report = Check_Report_AWS(self.metadata())
            report.region = table.region
            report.resource_id = table.name
            report.resource_arn = table_arn
            report.resource_tags = table.tags
            report.status = "FAIL"
            report.status_extended = f"DynamoDB table {table.name} does not automatically scale capacity with demand."
            if table.billing_mode == "PAY_PER_REQUEST":
                report.status = "PASS"
                report.status_extended = f"DynamoDB table {table.name} uses PAY_PER_REQUEST billing mode and automatically scales capacity with demand."
            elif table.billing_mode == "PROVISIONED":
                if table.read_autoscaling and table.write_autoscaling:
                    report.status = "PASS"
                    report.status_extended = f"DynamoDB table {table.name} is in PROVISIONED mode with auto scaling enabled for both read and write capacity units."
                else:
                    s = f"DynamoDB table {table.name} is in PROVISIONED mode without auto scaling enabled for "
                    if not table.read_autoscaling:
                        s += "read"
                        if not table.write_autoscaling:
                            s += " and write."
                        else:
                            s += "."
                    else:
                        s += "write."
                    report.status_extended = s
            findings.append(report)
        return findings
