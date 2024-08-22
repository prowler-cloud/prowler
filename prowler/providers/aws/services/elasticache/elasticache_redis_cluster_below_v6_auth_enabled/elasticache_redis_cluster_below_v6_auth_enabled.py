from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_below_v6_auth_enabled(Check):
    def execute(self):
        findings = []
        for cluster in elasticache_client.clusters.values():
            if (
                cluster.engine == "redis" and int(cluster.engine_version[0]) < 6
            ):  # major.minor.patch
                report = Check_Report_AWS(self.metadata())
                report.region = cluster.region
                report.resource_id = cluster.id
                report.resource_arn = cluster.arn
                report.resource_tags = cluster.tags
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {cluster.id}(v{cluster.engine_version}) does have AUTH enabled."

                if not cluster.auth_token_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Elasticache Redis cache cluster {cluster.id}(v{cluster.engine_version}) does not have AUTH enabled."
                findings.append(report)

        return findings
