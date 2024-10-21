from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_instance_no_public_ip(Check):
    def execute(self):
        findings = []

        # Iterate through EC2 instances
        for instance in ec2_client.instances:
            if instance.state != 'running':
                continue  # Skip non-running instances
            
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags

            has_public_ip = False

            # Check if the instance has a public IP directly
            if instance.public_ip:
                has_public_ip = True
                report.status = "FAIL"
                report.status_extended = f"EC2 instance {instance.id} has a public IP address {instance.public_ip}."
            
            # Check if any of the network interfaces have a public IP
            for network_interface in instance.network_interfaces:
                if network_interface.public_ip_addresses:
                    has_public_ip = True
                    report.status = "FAIL"
                    report.status_extended = f"EC2 instance {instance.id} has a public IP address on network interface {network_interface.id}."
                    break  # Stop after first public IP found
            
            if not has_public_ip:
                report.status = "PASS"
                report.status_extended = f"EC2 instance {instance.id} does not have a public IP address."

            findings.append(report)

        return findings
