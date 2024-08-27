from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_below_v6_auth_enabled(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            if int(repl_group.engine_version[0]) < 6:
                report = Check_Report_AWS(self.metadata())
                report.region = repl_group.region
                report.resource_id = repl_group.id
                report.resource_arn = repl_group.arn
                report.resource_tags = repl_group.tags
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {repl_group.id}(v{repl_group.engine_version}) does have AUTH enabled."

                if not repl_group.auth_token_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Elasticache Redis cache cluster {repl_group.id}(v{repl_group.engine_version}) does not have AUTH enabled."

                findings.append(report)

            else:
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {repl_group.id}(v{repl_group.engine_version}) does not have to use AUTH, but it should have Redis ACL ocnfigured."

        return findings
