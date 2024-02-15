from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_flow_log_more_than_90_days(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, security_groups in network_client.security_groups.items():
            for security_group in security_groups:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = security_group.name
                report.resource_id = security_group.id
                if security_group.flow_logs and security_group.flow_logs.__len__() > 0:
                    report.status = "PASS"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has flow logs enabled for more than 90 days"
                    has_failed = False
                    if not has_failed:
                        for flow_log in security_group.flow_logs:
                            if not has_failed:
                                if not flow_log.enabled:
                                    report.status = "FAIL"
                                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has flow logs disabled"
                                    has_failed = True
                                elif (
                                    flow_log.retention_policy.days < 90
                                    and not has_failed
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} flow logs retention policy is less than 90 days"
                                    has_failed = True
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has no flow logs"
                findings.append(report)

        return findings
