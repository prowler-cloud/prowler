from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_rcps_enforce_network_security(Check):
    def execute(self):
        findings = []

        if organizations_client.organization:
            if organizations_client.organization.policies is not None:
                report = Check_Report_AWS(
                    metadata=self.metadata(),
                    resource=organizations_client.organization,
                )
                report.resource_id = organizations_client.organization.id
                report.resource_arn = organizations_client.organization.arn
                report.region = organizations_client.region
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account."
                )

                if organizations_client.organization.status == "ACTIVE":
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enforcing network security controls."

                    # Check if Resource Control Policies are present
                    if "RESOURCE_CONTROL_POLICY" in organizations_client.organization.policies:
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )
                        
                        # Check for network security controls in RCPs
                        network_security_rcps = []
                        for policy in rcps:
                            # Check if policy enforces network security controls
                            if self._policy_enforces_network_security(policy):
                                network_security_rcps.append(policy)
                            
                        if network_security_rcps:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(network_security_rcps)} Resource Control Policies enforcing network security controls."
                
                findings.append(report)

        return findings
    
    def _policy_enforces_network_security(self, policy):
        """Check if a policy enforces network security controls"""
        # Get policy statements
        statements = policy.content.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Network security related services
        network_services = [
            "ec2", "vpc", "vpn", "directconnect", "apigateway", "elb", "elbv2", 
            "cloudfront", "route53", "globalaccelerator", "networkfirewall", "waf", "wafv2",
            "shield", "acm", "networkmanager"
        ]
        
        # Network security related actions
        network_actions = [
            "createnetworkacl", "createroute", "createinternetgateway", "attachinternetgateway",
            "authorizesecuritygroupingress", "authorizesecuritygroupegress",
            "createsecuritygroup", "modifyvpcattribute", "createvpc", "createsubnet",
            "createnatgateway", "createvpcendpoint", "deletevpcendpoints",
            "createloadbalancer", "createlistener", "createtargetgroup", "createcache",
            "createcluster", "createdbinstance", "modifysecuritygrouprules"
        ]
        
        # Network security related conditions
        network_conditions = [
            "sourcevpc", "sourcevpce", "sourceip", "ipaddress", "cidrrip", "cidrip", 
            "toport", "fromport", "sourcetype", "internetgateway", "vpcendpoint", 
            "publicip", "publiclyaccessible", "subnetid", "vpcid", "awsvpcConfiguration",
            "tlsversionforHttps"
        ]
        
        # Check statements for network security controls
        for statement in statements:
            # Check if statement is about preventing insecure network configurations
            if statement.get("Effect") == "Deny":
                # Check actions
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]
                
                action_str = str(actions).lower()
                
                # Check for network-related services in actions
                for service in network_services:
                    if service.lower() in action_str:
                        # Check for specific network actions that should be denied
                        for network_action in network_actions:
                            if network_action.lower() in action_str:
                                # Check conditions for network-related conditions
                                condition = statement.get("Condition", {})
                                if condition:
                                    condition_str = str(condition).lower()
                                    # Check for network security conditions
                                    for net_condition in network_conditions:
                                        if net_condition.lower() in condition_str:
                                            # This looks like a network security control
                                            return True
                
                # Also check conditions directly for network security requirements
                condition = statement.get("Condition", {})
                if condition:
                    condition_str = str(condition).lower()
                    # Conditions that specifically indicate network security controls
                    network_security_indicators = [
                        "0.0.0.0/0", "cidrip", "ec2:cidrip", "aws:sourcevpc", 
                        "aws:sourcevpce", "aws:sourceip", "vpc-", "vpce-", 
                        "tls1.0", "tls1.1", "publiclyaccessible", 
                        "ec2:isrestrictedmanagementport"
                    ]
                    
                    for indicator in network_security_indicators:
                        if indicator.lower() in condition_str:
                            return True
            
            # Also check if requiring specific security configurations
            elif statement.get("Effect") == "Allow" and "Condition" in statement:
                condition = statement.get("Condition", {})
                condition_str = str(condition).lower()
                
                # Look for conditions that enforce secure network configurations
                secure_network_indicators = [
                    "aws:securetransport", "true", "aws:vpce", "aws:sourcevpc",
                    "ec2:requireimdsv2", "true", "ec2:isrestrictedmanagementport", 
                    "tls1.2", "tls1.3"
                ]
                
                # Count how many secure network indicators are present
                indicator_count = sum(1 for indicator in secure_network_indicators 
                                      if indicator.lower() in condition_str)
                
                # If multiple indicators are present, it's likely enforcing network security
                if indicator_count >= 2:
                    return True
        
        # If no network security controls found
        return False