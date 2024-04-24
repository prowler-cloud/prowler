from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import (
    check_if_open_security_group_is_attached_to_instance,
    check_security_group,
)
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
                    instances_attached = (
                        check_if_open_security_group_is_attached_to_instance(
                            security_group=security_group,
                            vpc_client=vpc_client,
                            port="SSH",
                        )
                    )
                    if instances_attached:
                        for instance_attached in instances_attached:
                            report.status = "FAIL"
                            report.check_metadata.Severity = instance_attached[
                                "severity"
                            ]
                            report.status_extended = instance_attached["details"]
                            report.resource_details = instance_attached["instance_id"]
                            findings.append(report)
                    else:
                        findings.append(report)
                else:
                    findings.append(report)

        return findings
