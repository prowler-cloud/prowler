from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
    ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
)
from prowler.providers.aws.services.ec2.ec2_service import NetworkInterface
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_allow_ingress_from_internet_to_any_port(Check):
    def execute(self):
        findings = []
        for security_group_arn, security_group in ec2_client.security_groups.items():
            # Only execute the check if the check ec2_securitygroup_allow_ingress_from_internet_to_all_ports has not failed
            if not ec2_client.is_failed_check(
                ec2_securitygroup_allow_ingress_from_internet_to_all_ports.__name__,
                security_group_arn,
            ):
                # Check if ignoring flag is set and if the VPC and the SG is in use
                if ec2_client.provider.scan_unused_services or (
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
                    report.resource_arn = security_group_arn
                    report.resource_tags = security_group.tags
                    for ingress_rule in security_group.ingress_rules:
                        if check_security_group(
                            ingress_rule, "-1", ports=None, any_address=True
                        ):
                            self.check_enis(
                                report=report,
                                security_group_name=security_group.name,
                                security_group_id=security_group.id,
                                enis=security_group.network_interfaces,
                            )

                        if report.status == "FAIL":
                            break
                    findings.append(report)

        return findings

    def check_enis(
        self,
        report,
        security_group_name: str,
        security_group_id: str,
        enis: list[NetworkInterface],
    ):
        report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet but it is not attached to any network interface."
        for eni in enis:
            if eni.type in ec2_client.audit_config.get(
                "ec2_allowed_interface_types", []
            ):
                report.status = "PASS"
                report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet and it is attached to an allowed network interface type ({eni.type})."
                continue
            if eni.attachment.instance_owner_id in ec2_client.audit_config.get(
                "ec2_allowed_instance_owners", []
            ):
                report.status = "PASS"
                report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet and it is attached to an allowed network interface instance owner ({eni.attachment.instance_owner_id})."
                continue
            if eni.type not in ec2_client.audit_config.get(
                "ec2_allowed_interface_types", []
            ):
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet but its network interface type ({eni.type}) is not allowed."
            elif eni.attachment.instance_owner_id not in ec2_client.audit_config.get(
                "ec2_allowed_instance_owners", []
            ):
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet but its network interface instance owner ({eni.attachment.instance_owner_id}) is not allowed."
            else:
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group_name} ({security_group_id}) has at least one port open to the Internet but neither its network interface type ({eni.type}) nor its network interface instance owner ({eni.attachment.instance_owner_id}) are allowed."
            if report.status == "FAIL":
                break
