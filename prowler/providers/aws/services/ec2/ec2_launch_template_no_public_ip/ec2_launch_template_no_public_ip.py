from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_no_public_ip(Check):
    def execute(self):
        findings = []
        for template in ec2_client.launch_templates:
            report = Check_Report_AWS(self.metadata())
            report.region = template.region
            report.resource_id = template.id
            report.resource_arn = template.arn
            report.resource_tags = template.tags

            versions_with_autoassign_public_ip = []
            versions_with_network_interfaces_public_ip = []

            for version in template.versions:
                # Check if the launch template version assigns a public IP address
                if version.template_data.associate_public_ip_address:
                    versions_with_autoassign_public_ip.append(
                        str(version.version_number)
                    )
                if version.template_data.network_interfaces:
                    for network_interface in version.template_data.network_interfaces:
                        if network_interface.public_ip_addresses:
                            versions_with_network_interfaces_public_ip.append(
                                str(version.version_number)
                            )
                            break

            if (
                versions_with_autoassign_public_ip
                or versions_with_network_interfaces_public_ip
            ):
                report.status = "FAIL"

                if (
                    versions_with_autoassign_public_ip
                    and versions_with_network_interfaces_public_ip
                ):
                    report.status_extended = f"EC2 Launch Template {template.name} is configured to assign a public IP address to network interfaces upon launch in template versions: {', '.join(versions_with_autoassign_public_ip)} and is using a network interface with public IP addresses in template versions: {', '.join(versions_with_network_interfaces_public_ip)}."
                elif versions_with_autoassign_public_ip:
                    report.status_extended = f"EC2 Launch Template {template.name} is configured to assign a public IP address to network interfaces upon launch in template versions: {', '.join(versions_with_autoassign_public_ip)}."
                elif versions_with_network_interfaces_public_ip:
                    report.status_extended = f"EC2 Launch Template {template.name} is using a network interface with public IP addresses in template versions: {', '.join(versions_with_network_interfaces_public_ip)}."
            else:
                report.status = "PASS"
                report.status_extended = f"EC2 Launch Template {template.name} is neither configured to assign a public IP address to network interfaces upon launch nor using a network interface with public IP addresses."
            findings.append(report)

        return findings
