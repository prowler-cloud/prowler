from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_critical_event_subscription(Check):
    def execute(self):
        findings = []
        if rds_client.provider.scan_unused_services or rds_client.db_instances:
            for db_event in rds_client.db_event_subscriptions:
                report = Check_Report_AWS(metadata=self.metadata(), resource=db_event)
                report.status = "FAIL"
                report.status_extended = "RDS instance event categories of maintenance, configuration change, and failure are not subscribed."
                report.region = db_event.region
                report.resource_tags = db_event.tags
                if db_event.source_type == "db-instance" and db_event.enabled:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=db_event
                    )
                    if db_event.event_list == [] or set(db_event.event_list) == {
                        "maintenance",
                        "configuration change",
                        "failure",
                    }:
                        report.status = "PASS"
                        report.status_extended = "RDS instance events are subscribed."
                    elif set(db_event.event_list) == {"maintenance"}:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event categories of configuration change and failure are not subscribed."
                    elif set(db_event.event_list) == {"configuration change"}:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event categories of maintenance and failure are not subscribed."
                    elif set(db_event.event_list) == {"failure"}:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event categories of maintenance and configuration change are not subscribed."
                    elif set(db_event.event_list) == {
                        "maintenance",
                        "configuration change",
                    }:
                        report.status = "FAIL"
                        report.status_extended = (
                            "RDS instance event category of failure is not subscribed."
                        )
                    elif set(db_event.event_list) == {
                        "maintenance",
                        "failure",
                    }:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event category of configuration change is not subscribed."
                    elif set(db_event.event_list) == {
                        "configuration change",
                        "failure",
                    }:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event category of maintenance is not subscribed."
                    else:
                        report.status = "FAIL"
                        report.status_extended = "RDS instance event categories of maintenance, configuration change, and failure are not subscribed."

                report.resource_id = rds_client.audited_account
                report.resource_arn = rds_client._get_rds_arn_template(db_event.region)

                findings.append(report)

        return findings
