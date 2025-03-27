from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_resource_control_policies_s3_security(Check):
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
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enforcing S3 security settings."

                    # Check if Resource Control Policies are present
                    if "RESOURCE_CONTROL_POLICY" in organizations_client.organization.policies:
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )
                        
                        # Check for S3 security related RCPs
                        s3_security_rcps = []
                        for policy in rcps:
                            # The content is already parsed as JSON in the service implementation
                            # Look for S3 specific statements in the policy
                            s3_policy = False
                            statements = policy.content.get("Statement", [])
                            # Ensure statements is a list
                            if not isinstance(statements, list):
                                statements = [statements]
                                
                            for statement in statements:
                                # Check if the policy applies to S3 buckets
                                resources = statement.get("Resource", "")
                                if not isinstance(resources, list):
                                    resources = [resources]
                                    
                                # Check if S3 is mentioned in the resources
                                for resource in resources:
                                    if "s3" in resource.lower() or resource == "*":
                                        s3_policy = True
                                        break
                                
                                # Also check if it enforces specific S3 security settings
                                if "Effect" in statement and statement["Effect"] == "Deny":
                                    condition = statement.get("Condition", {})
                                    # Look for conditions related to S3 security settings
                                    if any(key in str(condition).lower() for key in [
                                        "s3:publicaccess", 
                                        "s3:encryption", 
                                        "s3:versioning",
                                        "s3:bucketlevel",
                                        "s3:objectlockconfig"
                                    ]):
                                        s3_policy = True
                                        break
                            
                            if s3_policy and policy.targets:
                                s3_security_rcps.append(policy)
                            
                        if s3_security_rcps:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(s3_security_rcps)} Resource Control Policies enforcing S3 security settings."
                
                findings.append(report)

        return findings