from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
    ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
)
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389(Check):
    def execute(self):
        findings = []
        check_ports = [3389]
        for security_group_arn, security_group in ec2_client.security_groups.items():
            # Check if ignoring flag is set and if the VPC and the SG is in use
            if ec2_client.provider.scan_unused_services or (
                security_group.vpc_id in vpc_client.vpcs
                and vpc_client.vpcs[security_group.vpc_id].in_use
                and len(security_group.network_interfaces) > 0
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = security_group.region
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have Microsoft RDP port 3389 open to the Internet."
                report.resource_details = security_group.name
                report.resource_id = security_group.id
                report.resource_arn = security_group_arn
                report.resource_tags = security_group.tags
                # only proceed if check "..._to_all_ports" did not run or did not FAIL to avoid to report open ports twice
                if not ec2_client.is_failed_check(
                    ec2_securitygroup_allow_ingress_from_internet_to_all_ports.__name__,
                    security_group_arn,
                ):
                    # Loop through every security group's ingress rule and check it
                    for ingress_rule in security_group.ingress_rules:
                        if check_security_group(
                            ingress_rule, "tcp", check_ports, any_address=True
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has Microsoft RDP port 3389 open to the Internet."
                            break
                else:
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) has all ports open to the Internet and therefore was not checked against the specific Microsoft RDP port 3389."

                findings.append(report)

        return findings
