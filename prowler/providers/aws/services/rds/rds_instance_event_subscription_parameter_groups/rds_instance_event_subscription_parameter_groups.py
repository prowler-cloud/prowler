from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_event_subscription_parameter_groups(Check):
    """Ensure RDS parameter group event categories of configuration change are subscribed.

    This check is useful to ensure we receive notification of events that may affect the security, availability, and reliability of the RDS database instances associated with these parameter groups.
    """

    def execute(self):
        """Execute the RDS Parameter Group events are subscribed check.

        Iterates through the RDS DB event subscriptions and checks if the event source is DB parameter group and the event list is empty (so it's suscribe to all categories) or contains only configuration change.

        Returns:
            List[Check_Report_AWS]: A list of reports for the matching RDS DB event subscriptions.
        """
        findings = []
        if rds_client.provider.scan_unused_services or rds_client.db_instances:
            subscriptions_by_region = {}
            for db_event in rds_client.db_event_subscriptions:
                subscriptions_by_region.setdefault(db_event.region, []).append(db_event)
            for region, subscriptions in subscriptions_by_region.items():
                # Only subscriptions for this check's source type say anything
                # about it; other subscriptions must not produce findings.
                matching_subscriptions = [
                    db_event
                    for db_event in subscriptions
                    if db_event.source_type == "db-parameter-group"
                ]
                if matching_subscriptions:
                    for db_event in matching_subscriptions:
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=db_event
                        )
                        if db_event.enabled and (
                            db_event.event_list == []
                            or db_event.event_list
                            == [
                                "configuration change",
                            ]
                        ):
                            report.status = "PASS"
                            report.status_extended = (
                                "RDS parameter group events are subscribed."
                            )
                        else:
                            report.status = "FAIL"
                            report.status_extended = "RDS parameter group event category of configuration change is not subscribed."
                        findings.append(report)
                else:
                    findings.append(self._account_fail_report(region))
        return findings

    def _account_fail_report(self, region):
        report = Check_Report_AWS(metadata=self.metadata(), resource={})
        report.status = "FAIL"
        report.status_extended = "RDS parameter group event categories of configuration change is not subscribed."
        report.resource_id = rds_client.audited_account
        report.resource_arn = rds_client._get_rds_arn_template(region)
        report.region = region
        return report
