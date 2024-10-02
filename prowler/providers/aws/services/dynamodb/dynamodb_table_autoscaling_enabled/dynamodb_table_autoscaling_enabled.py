from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.applicationautoscaling_client import (
    applicationautoscaling_client,
)
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_autoscaling_enabled(Check):
    def execute(self):
        findings = []
        scalable_targets = applicationautoscaling_client.scalable_targets
        dynamodb_scalable_targets = [
            target
            for target in scalable_targets
            if target.service_namespace == "dynamodb"
            and target.resource_id.startswith("table/")
        ]
        autoscaling_mapping = {}
        for target in dynamodb_scalable_targets:
            table_name = target.resource_id.split("/")[1]
            if table_name not in autoscaling_mapping:
                autoscaling_mapping[table_name] = {}
            autoscaling_mapping[table_name][target.scalable_dimension] = target

        for table_arn, table in dynamodb_client.tables.items():
            report = Check_Report_AWS(self.metadata())
            report.region = table.region
            report.resource_id = table.name
            report.resource_arn = table_arn
            report.resource_tags = table.tags
            report.status = "PASS"
            report.status_extended = (
                f"DynamoDB table {table.name} automatically scales capacity on demand."
            )
            if table.billing_mode == "PROVISIONED":
                read_autoscaling = False
                write_autoscaling = False

                if table.name in autoscaling_mapping:
                    if (
                        "dynamodb:table:ReadCapacityUnits"
                        in autoscaling_mapping[table.name]
                    ):
                        read_autoscaling = True
                    if (
                        "dynamodb:table:WriteCapacityUnits"
                        in autoscaling_mapping[table.name]
                    ):
                        write_autoscaling = True

                if read_autoscaling and write_autoscaling:
                    report.status = "PASS"
                    report.status_extended = f"DynamoDB table {table.name} is in provisioned mode with auto scaling enabled for both read and write capacity units."
                else:
                    missing_autoscaling = []
                    if not read_autoscaling:
                        missing_autoscaling.append("read")
                    if not write_autoscaling:
                        missing_autoscaling.append("write")

                    if missing_autoscaling:
                        report.status = "FAIL"
                        report.status_extended = f"DynamoDB table {table.name} is in provisioned mode without auto scaling enabled for {', '.join(missing_autoscaling)}."

            findings.append(report)

        return findings
