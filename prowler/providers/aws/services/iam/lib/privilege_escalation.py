from prowler.providers.aws.services.iam.lib.policy import get_policy_actions

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


def find_escalation_combinations(
    allowed_actions: set, denied_actions: set, denied_not_actions: set
) -> set:
    """
    find_escalation_combinations finds the privilege escalation combinations.
    Args:
        allowed_actions (set): The allowed actions.
        denied_actions (set): The denied actions.
        denied_not_actions (set): The denied not actions.
    Returns:
        set: The privilege escalation combinations.
    """
    # First, we need to perform a left join with ALLOWED_ACTIONS and DENIED_ACTIONS
    left_actions = allowed_actions.difference(denied_actions)
    # Then, we need to find the DENIED_NOT_ACTIONS in LEFT_ACTIONS
    if denied_not_actions:
        privileged_actions = left_actions.intersection(denied_not_actions)
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
                        api = api_action[0]
                        # Add permissions if the API is present
                        if api == "*":
                            policies_combination.add(val)

    return policies_combination


def check_privilege_escalation(policy: dict) -> str:
    """
    check_privilege_escalation checks if the policy allows privilege escalation.
    Args:
        policy (dict): The policy to check.
    Returns:
        str: The policies affected by privilege escalation, separated by spaces.
    """

    policies_affected = ""

    if policy:
        allowed_actions, denied_actions, denied_not_actions = get_policy_actions(policy)
        policies_combination = find_escalation_combinations(
            allowed_actions, denied_actions, denied_not_actions
        )

        # Check all policies combinations and see if matchs with some combo key
        combos = set()
        for (
            key,
            values,
        ) in privilege_escalation_policies_combination.items():
            intersection = policies_combination.intersection(values)
            if intersection == values:
                combos.add(key)

        if combos:
            policies_affected = " ".join(
                str(privilege_escalation_policies_combination[key]) for key in combos
            )

    return policies_affected
