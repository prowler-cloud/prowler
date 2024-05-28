from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_event_subscriptions(Check):
    def execute(self):
        findings = []
        security_group_event = False
        parameter_group_event = False
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.check_metadata.Severity = "high"
        report.status_extended = "RDS events are not subscribed."
        if rds_client.db_event_subscriptions != []:
            for db_event in rds_client.db_event_subscriptions:
                if db_event.enabled:
                    report.region = db_event.region
                    report.resource_id = db_event.source_type
                    report.resource_arn = db_event.event_arn
                    if db_event.source_type == "db-security-group":
                        if db_event.event_list == []:
                            report.status = "PASS"
                            report.check_metadata.Severity = "low"
                            report.status_extended = (
                                "RDS security group events are subscribed."
                            )
                            security_group_event = True

                            findings.append(report)
                    elif db_event.source_type == "db-parameter-group":
                        report.status = "PASS"
                        report.check_metadata.Severity = "low"
                        report.status_extended = (
                            "RDS parameter group change events are subscribed."
                        )
                        parameter_group_event = True

                        findings.append(report)

        else:
            findings.append(report)

        if report.status_extended != "RDS events are not subscribed.":
            if not security_group_event:
                report.status = "FAIL"
                report.check_metadata.Severity = "high"
                report.status_extended = 'RDS security group event categories of "configuration change" and "failure" are not subscribed.'

                findings.append(report)

            if not parameter_group_event:
                report.status = "FAIL"
                report.check_metadata.Severity = "medium"
                report.status_extended = (
                    "RDS parameter group change events are not subscribed."
                )

                findings.append(report)

        return findings
