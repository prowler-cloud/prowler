from re import search

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

# Based on:
# - https://bishopfox.com/blog/privilege-escalation-in-aws
# - https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py
# - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/


class iam_policy_allows_privilege_escalation(Check):
    def execute(self) -> Check_Report_AWS:
        privilege_escalation_policies_combination = {
            "CreatePolicyVersion": {"iam:CreatePolicyVersion"},
            "SetDefaultPolicyVersion": {"iam:SetDefaultPolicyVersion"},
            "iam:PassRole": {"iam:PassRole"},
            "PassRole+EC2": {
                "iam:PassRole",
                "ec2:RunInstances",
            },
            "PassRole+CreateLambda+Invoke": {
                "iam:PassRole",
                "lambda:CreateFunction",
                "lambda:InvokeFunction",
            },
            "PassRole+CreateLambda+ExistingDynamo": {
                "iam:PassRole",
                "lambda:CreateFunction",
                "lambda:CreateEventSourceMapping",
            },
            "PassRole+CreateLambda+NewDynamo": {
                "iam:PassRole",
                "lambda:CreateFunction",
                "lambda:CreateEventSourceMapping",
                "dynamodb:CreateTable",
                "dynamodb:PutItem",
            },
            "PassRole+GlueEndpoint": {
                "iam:PassRole",
                "glue:CreateDevEndpoint",
                "glue:GetDevEndpoint",
            },
            "PassRole+GlueEndpoints": {
                "iam:PassRole",
                "glue:CreateDevEndpoint",
                "glue:GetDevEndpoints",
            },
            "PassRole+CloudFormation": {
                "cloudformation:CreateStack",
                "cloudformation:DescribeStacks",
            },
            "PassRole+DataPipeline": {
                "datapipeline:CreatePipeline",
                "datapipeline:PutPipelineDefinition",
                "datapipeline:ActivatePipeline",
            },
            "GlueUpdateDevEndpoint": {"glue:UpdateDevEndpoint"},
            "GlueUpdateDevEndpoints": {"glue:UpdateDevEndpoint"},
            "lambda:UpdateFunctionCode": {"lambda:UpdateFunctionCode"},
            "iam:CreateAccessKey": {"iam:CreateAccessKey"},
            "iam:CreateLoginProfile": {"iam:CreateLoginProfile"},
            "iam:UpdateLoginProfile": {"iam:UpdateLoginProfile"},
            "iam:AttachUserPolicy": {"iam:AttachUserPolicy"},
            "iam:AttachGroupPolicy": {"iam:AttachGroupPolicy"},
            "iam:AttachRolePolicy": {"iam:AttachRolePolicy"},
            "AssumeRole+AttachRolePolicy": {"sts:AssumeRole", "iam:AttachRolePolicy"},
            "iam:PutGroupPolicy": {"iam:PutGroupPolicy"},
            "iam:PutRolePolicy": {"iam:PutRolePolicy"},
            "AssumeRole+PutRolePolicy": {"sts:AssumeRole", "iam:PutRolePolicy"},
            "iam:PutUserPolicy": {"iam:PutUserPolicy"},
            "iam:AddUserToGroup": {"iam:AddUserToGroup"},
            "iam:UpdateAssumeRolePolicy": {"iam:UpdateAssumeRolePolicy"},
            "AssumeRole+UpdateAssumeRolePolicy": {
                "sts:AssumeRole",
                "iam:UpdateAssumeRolePolicy",
            },
            # TO-DO: We have to handle AssumeRole just if the resource is * and without conditions
            # "sts:AssumeRole": {"sts:AssumeRole"},
        }

        findings = []

        # Iterate over all the IAM "Customer Managed" policies
        for policy in iam_client.policies:
            if policy.type == "Custom":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = policy.name
                report.resource_arn = policy.arn
                report.region = iam_client.region
                report.resource_tags = policy.tags
                report.status = "PASS"
                report.status_extended = f"Custom Policy {report.resource_arn} does not allow privilege escalation."

                # List of policy actions
                allowed_actions = set()
                denied_actions = set()
                denied_not_actions = set()

                # Recover all policy actions
                if policy.document:
                    if not isinstance(policy.document["Statement"], list):
                        policy_statements = [policy.document["Statement"]]
                    else:
                        policy_statements = policy.document["Statement"]
                    for statements in policy_statements:
                        # Recover allowed actions
                        if statements["Effect"] == "Allow":
                            if "Action" in statements:
                                if type(statements["Action"]) is str:
                                    allowed_actions.add(statements["Action"])
                                if type(statements["Action"]) is list:
                                    allowed_actions.update(statements["Action"])

                        # Recover denied actions
                        if statements["Effect"] == "Deny":
                            if "Action" in statements:
                                if type(statements["Action"]) is str:
                                    denied_actions.add(statements["Action"])
                                if type(statements["Action"]) is list:
                                    denied_actions.update(statements["Action"])

                            if "NotAction" in statements:
                                if type(statements["NotAction"]) is str:
                                    denied_not_actions.add(statements["NotAction"])
                                if type(statements["NotAction"]) is list:
                                    denied_not_actions.update(statements["NotAction"])

                    # First, we need to perform a left join with ALLOWED_ACTIONS and DENIED_ACTIONS
                    left_actions = allowed_actions.difference(denied_actions)
                    # Then, we need to find the DENIED_NOT_ACTIONS in LEFT_ACTIONS
                    if denied_not_actions:
                        privileged_actions = left_actions.intersection(
                            denied_not_actions
                        )
                    # If there is no Denied Not Actions
                    else:
                        privileged_actions = left_actions

                    # Store all the action's combinations
                    policies_combination = set()

                    for values in privilege_escalation_policies_combination.values():
                        for val in values:
                            val_set = set()
                            val_set.add(val)
                            # Look for specific api:action
                            if privileged_actions.intersection(val_set) == val_set:
                                policies_combination.add(val)
                            # Look for api:*
                            else:
                                for permission in privileged_actions:
                                    api = permission.split(":")[0]
                                    api_action = permission.split(":")[1]

                                    if api_action == "*":
                                        if search(api, val):
                                            policies_combination.add(val)

                    # Check all policies combinations and see if matchs with some combo key
                    combos = set()
                    for (
                        key,
                        values,
                    ) in privilege_escalation_policies_combination.items():
                        intersection = policies_combination.intersection(values)
                        if intersection == values:
                            combos.add(key)

                    if len(combos) != 0:
                        report.status = "FAIL"
                        policies_affected = ""
                        for key in combos:
                            policies_affected += (
                                str(privilege_escalation_policies_combination[key])
                                + " "
                            )

                        report.status_extended = (
                            f"Custom Policy {report.resource_arn} allows privilege escalation using the following actions: {policies_affected}".rstrip()
                            + "."
                        )
                findings.append(report)
        return findings
