from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_event_subscription_security_groups(Check):
    def execute(self):
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
                    if db_event.source_type == "db-security-group" and db_event.enabled
                ]
                if matching_subscriptions:
                    for db_event in matching_subscriptions:
                        report = self._account_fail_report(region, db_event)
                        if db_event.event_list == [] or set(db_event.event_list) == {
                            "failure",
                            "configuration change",
                        }:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=db_event
                            )
                            report.status = "PASS"
                            report.status_extended = (
                                "RDS security group events are subscribed."
                            )

                        elif db_event.event_list == ["configuration change"]:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=db_event
                            )
                            report.status = "FAIL"
                            report.status_extended = "RDS security group event category of failure is not subscribed."

                        elif db_event.event_list == ["failure"]:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=db_event
                            )
                            report.status = "FAIL"
                            report.status_extended = "RDS security group event category of configuration change is not subscribed."

                        findings.append(report)
                else:
                    findings.append(self._account_fail_report(region))

        return findings

    def _account_fail_report(self, region, db_event=None):
        # Without a matching subscription this finding is account-level:
        # build it from an empty resource so an unrelated subscription's
        # payload and tags cannot leak into it (a tag-based mutelist entry
        # on that subscription could otherwise mute this finding).
        report = Check_Report_AWS(
            metadata=self.metadata(),
            resource=db_event if db_event is not None else {},
        )
        report.status = "FAIL"
        report.status_extended = "RDS security group event categories of configuration change and failure are not subscribed."
        report.region = region
        report.resource_id = rds_client.audited_account
        report.resource_arn = rds_client._get_rds_arn_template(region)
        report.resource_tags = []
        return report
