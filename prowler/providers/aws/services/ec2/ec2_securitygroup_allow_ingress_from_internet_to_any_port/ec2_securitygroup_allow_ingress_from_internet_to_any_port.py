from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
    ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
)
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_allow_ingress_from_internet_to_any_port(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            # Check if ignoring flag is set and if the VPC and the SG is in use
            if not ec2_client.audit_info.ignore_unused_services or (
                security_group.vpc_id in vpc_client.vpcs
                and vpc_client.vpcs[security_group.vpc_id].in_use
                and len(security_group.network_interfaces) > 0
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = security_group.region
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have any port open to the Internet."
                report.resource_details = security_group.name
                report.resource_id = security_group.id
                report.resource_arn = security_group.arn
                report.resource_tags = security_group.tags
                # only proceed if check "..._to_all_ports" did not run or did not FAIL to avoid to report open ports twice
                if not ec2_client.is_failed_check(
                    ec2_securitygroup_allow_ingress_from_internet_to_all_ports.__name__,
                    security_group.arn,
                ):
                    # Loop through every security group's ingress rule and check it
                    for ingress_rule in security_group.ingress_rules:
                        if check_security_group(
                            ingress_rule, "-1", ports=None, any_address=True
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has at least one port open to the Internet."
                else:
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) has all ports open to the Internet and therefore was not checked against a specific port."

                findings.append(report)

        return findings
