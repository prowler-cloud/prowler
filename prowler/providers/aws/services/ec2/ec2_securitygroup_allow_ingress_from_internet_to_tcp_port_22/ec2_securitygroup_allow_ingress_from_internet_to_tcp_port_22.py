from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22(Check):
    def execute(self):
        findings = []
        check_ports = [22]
        for security_group in ec2_client.security_groups:
            sg_is_open = False
            # Check if ignoring flag is set and if the VPC and the SG is in use
            if ec2_client.provider.scan_unused_services or (
                security_group.vpc_id in vpc_client.vpcs
                and vpc_client.vpcs[security_group.vpc_id].in_use
                and len(security_group.network_interfaces) > 0
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = security_group.region
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have SSH port 22 open to the Internet."
                report.resource_details = security_group.name
                report.resource_id = security_group.id
                report.resource_arn = security_group.arn
                report.resource_tags = security_group.tags
                if not security_group.public_ports:
                    # Loop through every security group's ingress rule and check it
                    for ingress_rule in security_group.ingress_rules:
                        if check_security_group(
                            ingress_rule, "tcp", check_ports, any_address=True
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has SSH port 22 open to the Internet but it is not attached."
                            report.check_metadata.Severity = "medium"
                            sg_is_open = True
                            break
                if sg_is_open:
                    # Check if the security group is attached to any EC2 instance
                    for network_interface in security_group.network_interfaces:
                        instance_attached = network_interface.attachment.get(
                            "InstanceId"
                        )
                        if instance_attached:
                            report.status = "FAIL"
                            report.check_metadata.Severity = "high"
                            # Check if the EC2 instance has a public IP
                            if not network_interface.association.get("PublicIp"):
                                report.status_extended = f"EC2 Instance {instance_attached} has SSH exposed to 0.0.0.0/0 on private ip address {network_interface.private_ip}."
                            else:
                                report.status_extended = f"EC2 Instance {instance_attached} has SSH exposed to 0.0.0.0/0 on public ip address {network_interface.association.get('PublicIp')}."
                                # Check if EC2 instance is in a public subnet
                                if vpc_client.vpc_subnets[
                                    network_interface.subnet_id
                                ].public:
                                    report.status_extended = f"EC2 Instance {instance_attached} has SSH exposed to 0.0.0.0/0 on public ip address {network_interface.association.get('PublicIp')} within public subnet {network_interface.subnet_id}."
                                    report.check_metadata.Severity = "critical"

                findings.append(report)

        return findings
