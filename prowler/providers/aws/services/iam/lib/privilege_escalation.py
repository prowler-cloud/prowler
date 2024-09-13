from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.lib.policy import (
    check_invalid_not_actions,
    process_actions,
)

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
    "GlueUpdateDevEndpoints": {"glue:UpdateDevEndpoints"},
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


def find_privilege_escalation_combinations(
    allowed_actions: set,
    denied_actions: set,
    allowed_not_actions: set,
    denied_not_actions: set,
) -> set:
    """
    find_privilege_escalation_combinations finds the privilege escalation combinations.
    Args:
        allowed_actions (set): The allowed actions.
        denied_actions (set): The denied actions.
        allowed_not_actions (set): The allowed not actions.
        denied_not_actions (set): The denied not actions.
    Returns:
        set: The privilege escalation combinations.
    """

    # Store all the action's combinations
    policies_combination = set()
    hard_allowed_not_actions = set()

    try:
        # First, we need to perform a difference with allowed_actions and denied_actions
        allowed_actions = allowed_actions.difference(denied_actions)
        # Then, we need to do perform a difference with allowed_not_actions and denied_not_actions
        allowed_not_actions = allowed_not_actions.difference(denied_not_actions)
        # If there are allowed_not_actions, we have to check if there are allowed_actions that are not allowed by allowed_not_actions
        if allowed_not_actions:
            # If allowed_actions is *, we need to save allowed_not_actions since we cannot subtract them
            if "*" in allowed_actions:
                hard_allowed_not_actions = allowed_not_actions
            else:
                allowed_actions = allowed_actions - allowed_not_actions
        # If there are denied_not_actions, means that every other action is denied
        if denied_not_actions:
            allowed_actions = allowed_actions.intersection(denied_not_actions)
        for values in privilege_escalation_policies_combination.values():
            for val in values:
                val_set = set()
                val_set.add(val)
                # Look for specific api:action
                if allowed_actions.intersection(val_set) == val_set:
                    policies_combination.add(val)
                # Look for api:*
                else:
                    for permission in allowed_actions:
                        # Here we have to handle if the api-action is admin, so "*"
                        api_action = permission.split(":")
                        # len() == 2, so api:action
                        if len(api_action) == 2:
                            api = api_action[0]
                            action = api_action[1]
                            # Add permissions if the API is present
                            if action == "*":
                                val_api = val.split(":")[0]
                                if api == val_api:
                                    policies_combination.add(val)

                        # len() == 1, so *
                        elif len(api_action) == 1:
                            # Unless the action is *, we have to check if the action to evaluate is in the hard_allowed_not_actions
                            if (
                                not hard_allowed_not_actions
                                or val not in hard_allowed_not_actions
                            ):
                                api = api_action[0]
                                # Add permissions if the API is present
                                if api == "*":
                                    policies_combination.add(val)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return policies_combination


def check_privilege_escalation(policy: dict) -> str:
    """
    check_privilege_escalation checks if the policy allows privilege escalation.
    Args:
        policy (dict): The policy to check.
    Returns:
        str: The policies affected by privilege escalation, separated by commas.
    """

    policies_affected = ""

    if policy:
        allowed_actions = set()
        allowed_not_actions = set()
        denied_actions = set()
        denied_not_actions = set()

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect")
            actions = statement.get("Action")
            not_actions = statement.get("NotAction")

            if effect == "Allow":
                process_actions(effect, actions, allowed_actions)
                process_actions(effect, not_actions, allowed_not_actions)
            elif effect == "Deny":
                process_actions(effect, actions, denied_actions)
                process_actions(effect, not_actions, denied_not_actions)

        # If there is only NotAction, it allows the rest of the actions
        if not allowed_actions and allowed_not_actions:
            allowed_actions.add("*")
        # Check for invalid services in allowed NotAction
        if allowed_not_actions:
            invalid_not_actions = check_invalid_not_actions(allowed_not_actions)
            if invalid_not_actions:
                # Since it is an invalid NotAction, it allows all AWS actions
                allowed_actions.add("*")

        policies_combination = find_privilege_escalation_combinations(
            allowed_actions, denied_actions, allowed_not_actions, denied_not_actions
        )

        # Check all policies combinations and see if matches with some combo key
        combos = set()
        for (
            key,
            values,
        ) in privilege_escalation_policies_combination.items():
            intersection = policies_combination.intersection(values)
            if intersection == values:
                combos.add(key)

        if combos:
            policies_affected = (
                ", ".join(
                    str(privilege_escalation_policies_combination[key])
                    for key in combos
                )
                .replace("{", "")
                .replace("}", "")
            )

    return policies_affected
