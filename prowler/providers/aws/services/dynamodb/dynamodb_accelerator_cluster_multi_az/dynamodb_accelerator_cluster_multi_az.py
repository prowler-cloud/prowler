from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dax_client import dax_client


class dynamodb_accelerator_cluster_multi_az(Check):
    def execute(self):
        findings = []
        for cluster in dax_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.region = cluster.region
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = f"DAX cluster {cluster.name} does not have nodes in multiple availability zones."
            if len(cluster.node_azs) > 1:
                report.status = "PASS"
                report.status_extended = f"DAX cluster {cluster.name} has nodes in multiple availability zones."
            findings.append(report)
        return findings
