from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_event_subscription_security_groups(Check):
    def execute(self):
        findings = []
        if rds_client.provider.scan_unused_services or rds_client.db_instances:
            for db_event in rds_client.db_event_subscriptions:
                report = Check_Report_AWS(self.metadata())
                report.status = "FAIL"
                report.status_extended = "RDS security group event categories of configuration change and failure are not subscribed."
                report.resource_id = db_event.id
                report.resource_arn = db_event.arn
                report.region = db_event.region
                if db_event.source_type == "db-security-group" and db_event.enabled:
                    if db_event.event_list == []:
                        report.status = "PASS"
                        report.status_extended = (
                            "RDS security group events are subscribed."
                        )

                    elif db_event.event_list == ["configuration change"]:
                        report.status = "FAIL"
                        report.status_extended = "RDS security group event category of failure is not subscribed."

                    elif db_event.event_list == ["failure"]:
                        report.status = "FAIL"
                        report.status_extended = "RDS security group event category of configuration change is not subscribed."

                findings.append(report)

        return findings
