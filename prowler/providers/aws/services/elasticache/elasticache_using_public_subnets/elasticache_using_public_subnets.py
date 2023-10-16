from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_using_public_subnets(Check):
    def execute(self):
        findings = []
        for instance in elasticache_client.elasticache_instances:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = instance.cache_cluster_id
            report.resource_arn = instance.arn
            report.status = "PASS"
            report.status_extended = "Cluster isn't using public subnets."
            if len(instance.public_subnets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Cluster is using {', '.join(instance.public_subnets)} public subnets."
            findings.append(report)

        return findings
