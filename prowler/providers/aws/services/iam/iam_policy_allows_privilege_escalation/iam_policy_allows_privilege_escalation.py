from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

# Does the tool analyze both users and roles, or just one or the other? --> Everything using AttachementCount.
# Does the tool take a principal-centric or policy-centric approach? --> Policy-centric approach.
# Does the tool handle resource constraints? --> We don't check if the policy affects all resources or not, we check everything.
# Does the tool consider the permissions of service roles? --> Just checks policies.
# Does the tool handle transitive privesc paths (i.e., attack chains)? --> Not yet.
# Does the tool handle the DENY effect as expected? --> Yes, it checks DENY's statements with Action and NotAction.
# Does the tool handle NotAction as expected? --> Yes
# Does the tool handle Condition constraints? --> Not yet.
# Does the tool handle service control policy (SCP) restrictions? --> No, SCP are within Organizations AWS API.


class iam_policy_allows_privilege_escalation(Check):
    def execute(self) -> Check_Report_AWS:
        # Is necessary to include the "Action:*" for
        # each service that has a policy that could
        # allow for privilege escalation
        privilege_escalation_iam_actions = {
            "iam:AttachGroupPolicy",
            "iam:SetDefaultPolicyVersion2",
            "iam:AddUserToGroup",
            "iam:AttachRolePolicy",
            "iam:AttachUserPolicy",
            "iam:CreateAccessKey",
            "iam:CreatePolicyVersion",
            "iam:CreateLoginProfile",
            "iam:PassRole",
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:PutUserPolicy",
            "iam:SetDefaultPolicyVersion",
            "iam:UpdateAssumeRolePolicy",
            "iam:UpdateLoginProfile",
            "iam:*",
            "sts:AssumeRole",
            "sts:*",
            "ec2:RunInstances",
            "ec2:*",
            "lambda:CreateEventSourceMapping",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
            "lambda:UpdateFunctionCode",
            "lambda:*",
            "dynamodb:CreateTable",
            "dynamodb:PutItem",
            "dynamodb:*",
            "glue:CreateDevEndpoint",
            "glue:GetDevEndpoint",
            "glue:GetDevEndpoints",
            "glue:UpdateDevEndpoint",
            "glue:*",
            "cloudformation:CreateStack",
            "cloudformation:DescribeStacks",
            "cloudformation:*",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "datapipeline:ActivatePipeline",
            "datapipeline:*",
        }
        findings = []
        for policy in iam_client.customer_managed_policies:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = policy["PolicyName"]
            report.resource_arn = policy["Arn"]
            report.region = iam_client.region

            # List of policy actions
            allowed_actions = set()
            denied_actions = set()
            denied_not_actions = set()

            # Recover all policy actions
            if type(policy["PolicyDocument"]["Statement"]) != list:
                policy_statements = [policy["PolicyDocument"]["Statement"]]
            else:
                policy_statements = policy["PolicyDocument"]["Statement"]
            for statements in policy_statements:
                # Recover allowed actions
                if statements["Effect"] == "Allow":
                    if "Action" in statements:
                        if type(statements["Action"]) is str:
                            allowed_actions = {statements["Action"]}
                        if type(statements["Action"]) is list:
                            allowed_actions = set(statements["Action"])

                # Recover denied actions
                if statements["Effect"] == "Deny":
                    if "Action" in statements:
                        if type(statements["Action"]) is str:
                            denied_actions = {statements["Action"]}
                        if type(statements["Action"]) is list:
                            denied_actions = set(statements["Action"])

                    if "NotAction" in statements:
                        if type(statements["NotAction"]) is str:
                            denied_not_actions = {statements["NotAction"]}
                        if type(statements["NotAction"]) is list:
                            denied_not_actions = set(statements["NotAction"])

            # First, we need to perform a left join with ALLOWED_ACTIONS and DENIED_ACTIONS
            left_actions = allowed_actions.difference(denied_actions)
            # Then, we need to find the DENIED_NOT_ACTIONS in LEFT_ACTIONS
            if denied_not_actions:
                privileged_actions = left_actions.intersection(denied_not_actions)
            # If there is no Denied Not Actions
            else:
                privileged_actions = left_actions
            # Finally, check if there is a privilege escalation action within this policy
            policy_privilege_escalation_actions = privileged_actions.intersection(
                privilege_escalation_iam_actions
            )

            if len(policy_privilege_escalation_actions) == 0:
                report.status = "PASS"
                report.status_extended = f"Customer Managed IAM Policy {report.resource_arn} not allows for privilege escalation"
            else:
                report.status = "FAIL"
                report.status_extended = f"Customer Managed IAM Policy {report.resource_arn} allows for privilege escalation using the following actions: {policy_privilege_escalation_actions}"
            findings.append(report)
        return findings
