from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_customer_created_cmk_changes_alert_enabled(Check):
    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []
        found = False

        for alert in sls_client.alerts:
            query_list = alert.configuration.get("queryList", [])
            if not query_list:
                continue

            for query_obj in query_list:
                query = query_obj.get("query", "")
                if "Kms" in query and (
                    "DisableKey" in query
                    or "ScheduleKeyDeletion" in query
                    or "DeleteKeyMaterial" in query
                ):
                    found = True
                    report = CheckReportAlibabaCloud(
                        metadata=self.metadata(), resource=alert
                    )
                    report.status = "PASS"
                    report.status_extended = f"SLS Alert {alert.name} is configured for disabling or deletion of customer created CMKs."
                    report.resource_id = alert.name
                    report.resource_arn = alert.arn
                    report.region = alert.region
                    findings.append(report)
                    break

            if found:
                break

        if not found:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=sls_client.provider.identity
            )
            report.status = "FAIL"
            report.status_extended = "No SLS Alert configured for disabling or deletion of customer created CMKs."
            report.resource_id = sls_client.audited_account
            report.resource_arn = sls_client.provider.identity.identity_arn
            report.region = sls_client.region
            findings.append(report)

        return findings
