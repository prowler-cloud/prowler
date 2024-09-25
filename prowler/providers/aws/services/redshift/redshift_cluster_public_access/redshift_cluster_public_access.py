from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.redshift.redshift_client import redshift_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class redshift_cluster_public_access(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "PASS"
            report.status_extended = (
                f"Redshift Cluster {cluster.id} is not publicly accessible."
            )
            if cluster.endpoint_address and cluster.public_access:
                report.status = "FAIL"
                report.status_extended = f"Redshift Cluster {cluster.id} is publicly accessible at endpoint {cluster.endpoint_address}."
            elif (
                cluster.vpc_id
                and cluster.vpc_id in vpc_client.vpcs
                and vpc_client.vpcs[cluster.vpc_id].public
            ):
                report.status = "FAIL"
                report.status_extended = f"Redshift Cluster {cluster.id} is in a public VPC {cluster.vpc_id}."
            elif cluster.vpc_security_groups:
                for sg_id in cluster.vpc_security_groups:
                    sg_arn = f"arn:{redshift_client.audited_partition}:ec2:{cluster.region}:{redshift_client.audited_account}:security-group/{sg_id}"
                    if sg_arn in ec2_client.security_groups:
                        for ingress_rule in ec2_client.security_groups[
                            sg_arn
                        ].ingress_rules:
                            if check_security_group(
                                ingress_rule, "tcp", any_address=True
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"Redshift Cluster {cluster.id} is in VPC {cluster.vpc_id} with a public security group {sg_id}."

            findings.append(report)

        return findings
