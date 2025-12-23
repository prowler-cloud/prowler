from prowler.lib.check.models import Check, Check_Report
from prowler.providers.gcp.services.dns.dns_client import dns_client
from prowler.providers.gcp.services.compute.compute_client import compute_client

class dns_policy_logging_enabled(Check):
    def execute(self):
        findings = []

        # 1. Iterate through all VPC Networks
        for network in compute_client.networks:
            report = Check_Report(self.metadata(), network)
            
            # Manually fill report details
            report.project_id = compute_client.project_ids[0]
            report.resource_id = network.name
            report.resource_name = network.name  # FIX: Added this line
            report.resource_arn = str(network.id)
            report.location = "global"

            report.status = "FAIL"
            report.status_extended = f"VPC Network {network.name} does NOT have Cloud DNS logging enabled."

            # 2. Check against all DNS Policies
            for policy in dns_client.policies:
                if policy.networks:
                    for policy_network_url in policy.networks:
                        # Check if the network name is inside the policy network URL
                        if f"/networks/{network.name}" in policy_network_url or network.name == policy_network_url:
                            
                            # We found the policy attached to this VPC. Now check logging.
                            if policy.logging:
                                report.status = "PASS"
                                report.status_extended = f"VPC Network {network.name} has Cloud DNS logging enabled via policy {policy.name}."
                            
                            # Found the specific policy for this VPC, stop checking other policies
                            break 
                
                # If we passed, stop checking other policies
                if report.status == "PASS":
                    break

            findings.append(report)

        return findings