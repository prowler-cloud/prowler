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
                            if attached_rcps:
                                report.status = "PASS"
                                report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(attached_rcps)} Resource Control Policies attached to targets."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"AWS Organization {organizations_client.organization.id} has Resource Control Policies, but none are attached to targets."

                findings.append(report)

        return findings
