from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import elasticache_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class elasticache_using_public_subnets(Check):
    def execute(self):
        findings = []
        vpc_subnets = vpc_client.vpc_subnets
        for instance in elasticache_client.elasticache_instances:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = instance.cache_cluster_id
            report.resource_arn = instance.arn
            report.status = "PASS"
            report.status_extended = (
                "Cluster isn't using public subnets."
            )
            public_subnets = []
            # print(instance.subnet_group)
            for subnets in instance.subnet_group:
                for subnet in subnets["Subnets"]:
                    if vpc_subnets[subnet["SubnetIdentifier"]].public:
                        public_subnets.append(vpc_subnets[subnet["SubnetIdentifier"]].id)
            if len(public_subnets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Cluster is using {', '.join(public_subnets)} public subnets."
            findings.append(report)

        return findings
