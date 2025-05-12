from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_rcps_enforce_iam_controls(Check):
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
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enforcing IAM security controls."

                    # Check if Resource Control Policies are present
                    if (
                        "RESOURCE_CONTROL_POLICY"
                        in organizations_client.organization.policies
                    ):
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )

                        # Check for IAM security controls in RCPs
                        iam_security_rcps = []
                        for policy in rcps:
                            # Check if policy enforces IAM security controls
                            if self._policy_enforces_iam_controls(policy):
                                iam_security_rcps.append(policy)

                        if iam_security_rcps:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(iam_security_rcps)} Resource Control Policies enforcing IAM security controls."

                findings.append(report)

        return findings

    def _policy_enforces_iam_controls(self, policy):
        """Check if a policy enforces IAM security controls"""
        # Get policy statements
        statements = policy.content.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        # IAM-related actions to look for
        iam_actions = [
            "iam:create",
            "iam:delete",
            "iam:update",
            "iam:put",
            "iam:attach",
            "iam:detach",
            "iam:add",
            "iam:remove",
            "iam:pass",
            "iam:getuser",
            "iam:addrole",
            "iam:createuser",
            "iam:createlogin",
            "iam:createaccesskey",
        ]

        # IAM-related conditions to look for
        iam_conditions = [
            "aws:multifactorauthpresent",
            "aws:principalarn",
            "aws:principaltype",
            "aws:principaltag",
            "aws:tokenissuedate",
            "iam:permissionsboundary",
            "iam:passedtoprincipalarn",
        ]

        # Check statements for IAM security controls
        for statement in statements:
            # If the statement is a deny for IAM actions
            if statement.get("Effect") == "Deny":
                # Check actions
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]

                # Check for IAM-related actions
                for action in actions:
                    action = action.lower() if isinstance(action, str) else ""
                    if action.startswith("iam:") or any(
                        iam_action in action for iam_action in iam_actions
                    ):
                        return True

                # Check conditions for IAM-related conditions
                condition = statement.get("Condition", {})
                condition_str = str(condition).lower()

                # Check for IAM-related conditions
                for iam_condition in iam_conditions:
                    if iam_condition in condition_str:
                        return True

            # Also check for permissions boundaries enforcement
            if "Resource" in statement and "Condition" in statement:
                resource = statement.get("Resource", "")
                condition = statement.get("Condition", {})

                # Check if resource includes IAM roles/users
                if isinstance(resource, str) and (
                    "iam" in resource.lower()
                    or "role" in resource.lower()
                    or "user" in resource.lower()
                ):
                    # Check conditions for permissions boundaries
                    condition_str = str(condition).lower()
                    if (
                        "permissionsboundary" in condition_str
                        or "aws:principalarn" in condition_str
                    ):
                        return True

        # If no IAM security controls found
        return False
