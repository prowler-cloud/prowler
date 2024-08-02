from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_auto_minor_version_upgrades(Check):
    def execute(self):
        findings = []
        for cluster in elasticache_client.clusters.values():
            if cluster.engine == "redis":
                report = Check_Report_AWS(self.metadata())
                report.region = cluster.region
                report.resource_id = cluster.id
                report.resource_arn = cluster.arn
                report.resource_tags = cluster.tags
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {cluster.id} does have automated minor version upgrades enabled."

                if not getattr(cluster, "auto_minor_version_upgrade", False):
                    report.status = "FAIL"
                    report.status_extended = f"Elasticache Redis cache cluster {cluster.id} does not have automated minor version upgrades enabled."
                    findings.append(report)
                    break

                findings.append(report)

        return findings
