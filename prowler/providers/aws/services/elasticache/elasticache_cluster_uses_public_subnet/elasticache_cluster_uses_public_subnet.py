from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class elasticache_cluster_uses_public_subnet(Check):
    def execute(self):
        findings = []
        for cluster in elasticache_client.clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.region = cluster.region

            report.status = "PASS"
            report.status_extended = (
                f"Cluster {cluster.id} is not using public subnets."
            )

            public_subnets = []
            for subnet in cluster.subnets:
                if vpc_client.vpc_subnets[subnet].public:
                    public_subnets.append(vpc_client.vpc_subnets[subnet].id)

            if len(public_subnets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Cluster {cluster.id} is using {', '.join(public_subnets)} public subnets."

            findings.append(report)

        return findings
