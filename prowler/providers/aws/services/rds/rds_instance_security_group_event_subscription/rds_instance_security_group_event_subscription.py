from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_security_group_event_subscription(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.check_metadata.Severity = "medium"
        report.status_extended = 'RDS security group event categories of "configuration change" and "failure" are not subscribed.'
        report.region = rds_client.region
        if rds_client.db_event_subscriptions != []:
            for db_event in rds_client.db_event_subscriptions:
                if db_event.source_type == "db-security-group" and db_event.enabled:
                    report.region = db_event.region
                    report.resource_id = db_event.source_type
                    report.resource_arn = db_event.event_arn
                    if db_event.event_list == []:
                        report.status = "PASS"
                        report.status_extended = (
                            "RDS security group events are subscribed."
                        )

                        findings.append(report)
                    elif db_event.event_list == ["configuration change"]:
                        report.status = "FAIL"
                        report.status_extended = 'RDS security group event category of "failure" is not subscribed.'

                        findings.append(report)
                    elif db_event.event_list == ["failure"]:
                        report.status = "FAIL"
                        report.status_extended = 'RDS security group event category of "configuration change" is not subscribed.'

                        findings.append(report)

                else:
                    findings.append(report)

        else:
            findings.append(report)

        return findings
