from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_uses_a_public_subnet(Check):
    def execute(self):
        findings = []
        for cluster in neptune_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.status = "PASS"
            report.status_extended = "Cluster isn't using public subnets."
            if len(cluster.public_subnets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Cluster is using {', '.join(cluster.public_subnets)} public subnets."

            findings.append(report)

        return findings
