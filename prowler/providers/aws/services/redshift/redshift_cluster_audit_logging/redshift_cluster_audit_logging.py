from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_audit_logging(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.status = "PASS"
            report.status_extended = (
                f"Redshift Cluster {cluster.arn} has audit logging enabled"
            )
            if not cluster.logging_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Redshift Cluster {cluster.arn} has audit logging disabled"
                )

            findings.append(report)

        return findings
