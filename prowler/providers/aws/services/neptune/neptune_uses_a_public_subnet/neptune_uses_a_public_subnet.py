from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import (
    neptune_client,
)
from prowler.providers.aws.services.neptune.neptune_client import neptune_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class neptune_uses_a_public_subnet(Check):
    def execute(self):
        findings = []
        vpc_subnets = vpc_client.vpc_subnets
        for cluster in neptune_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.status = "PASS"
            report.status_extended = (
                "Cluster isn't using public subnets."
            )
            public_subnets = []
            for subnets in cluster.subnet_group:
                for subnet in subnets["Subnets"]:
                    if vpc_subnets[subnet["SubnetIdentifier"]].public:
                        public_subnets.append(vpc_subnets[subnet["SubnetIdentifier"]].id)
            if len(public_subnets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Cluster is using {', '.join(public_subnets)} public subnets."

            findings.append(report)

        return findings
