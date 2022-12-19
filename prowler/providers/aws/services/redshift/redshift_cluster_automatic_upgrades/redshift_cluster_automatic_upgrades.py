from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_automatic_upgrades(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.status = "PASS"
            report.status_extended = (
                f"Redshift Cluster {cluster.arn} has AllowVersionUpgrade enabled"
            )
            if not cluster.allow_version_upgrade:
                report.status = "FAIL"
                report.status_extended = (
                    f"Redshift Cluster {cluster.arn} has AllowVersionUpgrade disabled"
                )

            findings.append(report)

        return findings
