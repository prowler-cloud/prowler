from py_iam_expand.actions import expand_actions

from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.lib.policy import get_effective_actions

# Does the tool analyze both users and roles, or just one or the other? --> Everything using AttachementCount.
# Does the tool take a principal-centric or policy-centric approach? --> Policy-centric approach.
# Does the tool handle resource constraints? --> We don't check if the policy affects all resources or not, we check everything.
# Does the tool consider the permissions of service roles? --> Just checks policies.
# Does the tool handle transitive privesc paths (i.e., attack chains)? --> Not yet.
# Does the tool handle the DENY effect as expected? --> Yes, it checks DENY's statements with Action and NotAction.
# Does the tool handle NotAction as expected? --> Yes
# Does the tool handle NotAction with invalid actions as expected? --> Yes
# Does the tool handle Condition constraints? --> Not yet.
# Does the tool handle service control policy (SCP) restrictions? --> No, SCP are within Organizations AWS API.

# Based on:
# - https://bishopfox.com/blog/privilege-escalation-in-aws
# - https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py
# - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

privilege_escalation_policies_combination = {
    "OverPermissiveIAM": {"iam:*"},
    "IAMPut": {"iam:Put*"},
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
        "iam:PassRole",
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
    },
    "PassRole+DataPipeline": {
        "iam:PassRole",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline",
    },
    "GlueUpdateDevEndpoint": {"glue:UpdateDevEndpoint"},
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


def check_privilege_escalation(policy: dict) -> str:
    """
    Checks if the policy allows known privilege escalation combinations.

    Args:
        policy (dict): The IAM policy document.

    Returns:
        str: A comma-separated string of the privilege escalation actions found,
            or an empty string if none are found.
    """
    policies_affected = ""
    if not policy:
        return policies_affected

    try:
        effective_allowed_actions = get_effective_actions(policy)

        matched_combo_actions = set()
        matched_combo_keys = set()

        for (
            combo_key,
            required_actions_patterns,
        ) in privilege_escalation_policies_combination.items():
            # Expand the required actions for the current combo
            expanded_required_actions = set()
            for action_pattern in required_actions_patterns:
                expanded_required_actions.update(expand_actions(action_pattern))

            # Check if all expanded required actions are present in the effective actions
            if expanded_required_actions and expanded_required_actions.issubset(
                effective_allowed_actions
            ):
                # If match, store the original patterns and the key
                matched_combo_actions.update(required_actions_patterns)
                matched_combo_keys.add(combo_key)

        if matched_combo_keys:
            # Use the original patterns from the matched combos for the output
            policies_affected = ", ".join(
                f"'{action}'" for action in sorted(list(matched_combo_actions))
            )
            # Alternative: Output based on combo keys
            # print("DEBUG: matched_combo_keys =", ", ".join(sorted(list(matched_combo_keys))))

    except Exception as error:
        logger.error(
            f"Error checking privilege escalation for policy: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return policies_affected
