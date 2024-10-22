from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.emr.emr_client import emr_client


class emr_kerberos_enabled(Check):
    def execute(self):
        findings = []

        for cluster in emr_client.clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags

            if hasattr(cluster, 'kerberos_enabled') and cluster.kerberos_enabled:
                report.status = "PASS"
                report.status_extended = f"EMR cluster {cluster.name} has Kerberos enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"EMR cluster {cluster.name} does not have Kerberos enabled."

            findings.append(report)

        return findings
