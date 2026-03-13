from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
    ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
)
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip(Check):
    def execute(self):
        findings = []
        for security_group_arn, security_group in ec2_client.security_groups.items():
            # Skip if already flagged by the all_ports check to avoid duplicate reporting
            if ec2_client.is_failed_check(
                ec2_securitygroup_allow_ingress_from_internet_to_all_ports.__name__,
                security_group_arn,
            ):
                continue

            # Check if ignoring flag is set and if the VPC and the SG is in use
            if ec2_client.provider.scan_unused_services or (
                security_group.vpc_id in vpc_client.vpcs
                and vpc_client.vpcs[security_group.vpc_id].in_use
                and len(security_group.network_interfaces) > 0
            ):
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=security_group
                )
                report.resource_details = security_group.name
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have any port open to a public IP address."

                for ingress_rule in security_group.ingress_rules:
                    # any_address=False means any globally routable IP triggers it,
                    # not just 0.0.0.0/0 or ::/0
                    if check_security_group(
                        ingress_rule, "-1", any_address=False, all_ports=True
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has a port open to a public IP address in ingress rule."
                        break

                findings.append(report)

        return findings
