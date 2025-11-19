from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_resource_control_policies_enabled(Check):
    def execute(self):
        findings = []

        if organizations_client.organization:
            if (
                organizations_client.organization.policies is not None
            ):  # Access denied to list policies
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
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enabled."

                    # Check if Resource Control Policies are present and attached to targets
                    if (
                        "RESOURCE_CONTROL_POLICY"
                        in organizations_client.organization.policies
                    ):
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )
                        if rcps:
                            # Check if any RCP is attached to targets
                            attached_rcps = [
                                policy for policy in rcps if policy.targets
                            ]
                            
                            # Filter out RCPFullAWSAccess policies as they don't provide security value
                            restrictive_rcps = [
                                policy for policy in attached_rcps 
                                if not self._is_rcp_full_aws_access(policy)
                            ]
                            
                            if restrictive_rcps:
                                report.status = "PASS"
                                report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(restrictive_rcps)} restrictive Resource Control Policies attached to targets."
                            elif attached_rcps:
                                # Only RCPFullAWSAccess is attached
                                report.status = "FAIL"
                                report.status_extended = f"AWS Organization {organizations_client.organization.id} has Resource Control Policies enabled but only RCPFullAWSAccess is attached, which provides no security value."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"AWS Organization {organizations_client.organization.id} has Resource Control Policies, but none are attached to targets."

                findings.append(report)

        return findings
    
    def _is_rcp_full_aws_access(self, policy):
        """Check if the policy is the default RCPFullAWSAccess policy"""
        # RCPFullAWSAccess typically has an ID containing "FullAWSAccess" and allows all actions
        if policy.id and "FullAWSAccess" in policy.id:
            return True
        
        # Check if policy content allows all actions without restrictions
        statements = policy.content.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            # If there's an Allow statement with "*" action and no conditions, it's likely RCPFullAWSAccess
            if (statement.get("Effect") == "Allow" and
                statement.get("Action") == "*" and
                statement.get("Resource") == "*" and
                not statement.get("Condition")):
                return True
        
        return False
