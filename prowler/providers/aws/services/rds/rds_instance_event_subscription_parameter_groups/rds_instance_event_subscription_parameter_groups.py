from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_event_subscription_parameter_groups(Check):
    def execute(self):
        findings = []
        if rds_client.provider.scan_unused_services or rds_client.db_instances:
            for db_event in rds_client.db_event_subscriptions:
                report = Check_Report_AWS(self.metadata())
                report.status = "FAIL"
                report.status_extended = "RDS parameter group event categories of configuration change is not subscribed."
                report.resource_id = rds_client.audited_account
                report.resource_arn = rds_client._get_rds_arn_template(db_event.region)
                report.region = db_event.region
                report.resource_tags = []
                if db_event.source_type == "db-parameter-group" and db_event.enabled:
                    if db_event.event_list == [] or db_event.event_list == [
                        "configuration change",
                    ]:
                        report.resource_id = db_event.id
                        report.resource_arn = db_event.arn
                        report.resource_tags = db_event.tags
                        report.status = "PASS"
                        report.status_extended = (
                            "RDS parameter group events are subscribed."
                        )
                findings.append(report)

        return findings
