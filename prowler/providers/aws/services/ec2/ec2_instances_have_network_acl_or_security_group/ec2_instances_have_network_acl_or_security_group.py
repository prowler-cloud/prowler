from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_instances_have_network_acl_or_security_group(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = f"Instance {instance.id} has network ACLs and/or security groups attached."

            # Check if the instance has security groups
            if instance.security_groups:
                findings.append(report)
                continue

            # Check if the instance is associated with a subnet that has a network ACL
            network_acl_attached = False
            subnet_id = instance.subnet_id
            if subnet_id and subnet_id in vpc_client.vpc_subnets:
                subnet = vpc_client.vpc_subnets[subnet_id]
                if subnet.network_acl_id and subnet.network_acl_id in vpc_client.network_acls:
                    network_acl_attached = True

            if not network_acl_attached:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.id} does not have security groups or network ACLs attached."

            findings.append(report)
        return findings
