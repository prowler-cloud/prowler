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
# - https://github.com/DataDog/pathfinding.cloud (AWS IAM Privilege Escalation Path Library)

privilege_escalation_policies_combination = {
    # IAM self-escalation and policy manipulation
    "OverPermissiveIAM": {"iam:*"},
    "IAMPut": {"iam:Put*"},
    "CreatePolicyVersion": {"iam:CreatePolicyVersion"},
    "SetDefaultPolicyVersion": {"iam:SetDefaultPolicyVersion"},
    "iam:CreateAccessKey": {"iam:CreateAccessKey"},
    "iam:CreateLoginProfile": {"iam:CreateLoginProfile"},
    "iam:UpdateLoginProfile": {"iam:UpdateLoginProfile"},
    "iam:AttachUserPolicy": {"iam:AttachUserPolicy"},
    "iam:AttachGroupPolicy": {"iam:AttachGroupPolicy"},
    "iam:AttachRolePolicy": {"iam:AttachRolePolicy"},
    "iam:PutGroupPolicy": {"iam:PutGroupPolicy"},
    "iam:PutRolePolicy": {"iam:PutRolePolicy"},
    "iam:PutUserPolicy": {"iam:PutUserPolicy"},
    "iam:AddUserToGroup": {"iam:AddUserToGroup"},
    "iam:UpdateAssumeRolePolicy": {"iam:UpdateAssumeRolePolicy"},
    # IAM chained privilege escalation patterns
    "CreateAccessKey+DeleteAccessKey": {
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
    },
    "AttachUserPolicy+CreateAccessKey": {
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
    },
    "PutUserPolicy+CreateAccessKey": {
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
    },
    "AttachRolePolicy+UpdateAssumeRolePolicy": {
        "iam:AttachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
    },
    "CreatePolicyVersion+UpdateAssumeRolePolicy": {
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
    },
    "PutRolePolicy+UpdateAssumeRolePolicy": {
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
    },
    # STS-based privilege escalation patterns
    "AssumeRole+AttachRolePolicy": {"sts:AssumeRole", "iam:AttachRolePolicy"},
    "AssumeRole+PutRolePolicy": {"sts:AssumeRole", "iam:PutRolePolicy"},
    "AssumeRole+UpdateAssumeRolePolicy": {
        "sts:AssumeRole",
        "iam:UpdateAssumeRolePolicy",
    },
    "AssumeRole+CreatePolicyVersion": {
        "sts:AssumeRole",
        "iam:CreatePolicyVersion",
    },
    # EC2-based privilege escalation patterns
    "PassRole+EC2": {
        "iam:PassRole",
        "ec2:RunInstances",
    },
    "PassRole+EC2SpotInstances": {
        "iam:PassRole",
        "ec2:RequestSpotInstances",
    },
    # Prerequisite: Existing EC2 instance with admin role attached
    "EC2ModifyInstanceAttribute": {
        "ec2:ModifyInstanceAttribute",
        "ec2:StopInstances",
        "ec2:StartInstances",
    },
    # Prerequisite: Existing launch template used by instances with admin role
    "EC2ModifyLaunchTemplate": {
        "ec2:CreateLaunchTemplateVersion",
        "ec2:ModifyLaunchTemplate",
    },
    # EC2 Instance Connect privilege escalation
    # Prerequisite: Running EC2 with Instance Connect enabled and admin role
    "EC2InstanceConnect+SendSSHPublicKey": {
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2:DescribeInstances",
    },
    # Lambda-based privilege escalation patterns
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
    "PassRole+CreateLambda+AddPermission": {
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:AddPermission",
    },
    # Prerequisite: Existing Lambda function with admin execution role
    "lambda:UpdateFunctionCode": {"lambda:UpdateFunctionCode"},
    # Prerequisite: Existing Lambda function with admin execution role
    "lambda:UpdateFunctionConfiguration": {"lambda:UpdateFunctionConfiguration"},
    # Prerequisite: Existing Lambda function with admin execution role
    "UpdateFunctionCode+InvokeFunction": {
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction",
    },
    # Prerequisite: Existing Lambda function with admin execution role
    "UpdateFunctionCode+AddPermission": {
        "lambda:UpdateFunctionCode",
        "lambda:AddPermission",
    },
    # Glue-based privilege escalation patterns
    "PassRole+GlueCreateDevEndpoint": {
        "iam:PassRole",
        "glue:CreateDevEndpoint",
    },
    # Prerequisite: Existing Glue dev endpoint with admin role
    "GlueUpdateDevEndpoint": {"glue:UpdateDevEndpoint"},
    "PassRole+GlueCreateJob+StartJobRun": {
        "iam:PassRole",
        "glue:CreateJob",
        "glue:StartJobRun",
    },
    "PassRole+GlueCreateJob+CreateTrigger": {
        "iam:PassRole",
        "glue:CreateJob",
        "glue:CreateTrigger",
    },
    # Prerequisite: Existing Glue job
    "PassRole+GlueUpdateJob+StartJobRun": {
        "iam:PassRole",
        "glue:UpdateJob",
        "glue:StartJobRun",
    },
    # Prerequisite: Existing Glue job
    "PassRole+GlueUpdateJob+CreateTrigger": {
        "iam:PassRole",
        "glue:UpdateJob",
        "glue:CreateTrigger",
    },
    # CloudFormation-based privilege escalation patterns
    "PassRole+CloudFormationCreateStack": {
        "iam:PassRole",
        "cloudformation:CreateStack",
    },
    # Prerequisite: Existing CloudFormation stack with admin service role
    "CloudFormationUpdateStack": {"cloudformation:UpdateStack"},
    "PassRole+CloudFormationCreateStackSet": {
        "iam:PassRole",
        "cloudformation:CreateStackSet",
        "cloudformation:CreateStackInstances",
    },
    # Prerequisite: Existing CloudFormation StackSet
    "PassRole+CloudFormationUpdateStackSet": {
        "iam:PassRole",
        "cloudformation:UpdateStackSet",
    },
    # Prerequisite: Existing CloudFormation stack with admin service role
    "CloudFormationChangeSet": {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
    },
    # DataPipeline-based privilege escalation patterns
    "PassRole+DataPipeline": {
        "iam:PassRole",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline",
    },
    # CodeStar-based privilege escalation patterns
    "PassRole+CodeStar": {
        "iam:PassRole",
        "codestar:CreateProject",
    },
    # CodeBuild-based privilege escalation patterns
    "PassRole+CodeBuildCreateProject+StartBuild": {
        "iam:PassRole",
        "codebuild:CreateProject",
        "codebuild:StartBuild",
    },
    "PassRole+CodeBuildCreateProject+StartBuildBatch": {
        "iam:PassRole",
        "codebuild:CreateProject",
        "codebuild:StartBuildBatch",
    },
    # Prerequisite: Existing CodeBuild project with admin service role
    "CodeBuildStartBuild": {"codebuild:StartBuild"},
    # Prerequisite: Existing CodeBuild project with admin service role
    "CodeBuildStartBuildBatch": {"codebuild:StartBuildBatch"},
    # AutoScaling-based privilege escalation patterns
    "PassRole+CreateAutoScaling": {
        "iam:PassRole",
        "autoscaling:CreateAutoScalingGroup",
        "autoscaling:CreateLaunchConfiguration",
    },
    # Prerequisite: Existing Auto Scaling group
    "PassRole+UpdateAutoScaling": {
        "iam:PassRole",
        "autoscaling:UpdateAutoScalingGroup",
        "autoscaling:CreateLaunchConfiguration",
    },
    # ECS-based privilege escalation patterns
    "PassRole+ECS+RegisterTaskDef+CreateService": {
        "iam:PassRole",
        "ecs:RegisterTaskDefinition",
        "ecs:CreateService",
    },
    "PassRole+ECS+RegisterTaskDef+RunTask": {
        "iam:PassRole",
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask",
    },
    "PassRole+ECS+RegisterTaskDef+StartTask": {
        "iam:PassRole",
        "ecs:RegisterTaskDefinition",
        "ecs:StartTask",
    },
    # Reference: https://labs.reversec.com/posts/2025/08/another-ecs-privilege-escalation-path
    "PassRole+ECS+StartTask": {
        "iam:PassRole",
        "ecs:StartTask",
        "ecs:RegisterContainerInstance",
        "ecs:DeregisterContainerInstance",
    },
    # Prerequisite: Existing ECS cluster and task definition with admin role
    "PassRole+ECS+RunTask": {
        "iam:PassRole",
        "ecs:RunTask",
    },
    # Prerequisite: Running ECS task with ECS Exec enabled and admin task role
    "ECS+ExecuteCommand": {
        "ecs:ExecuteCommand",
        "ecs:DescribeTasks",
    },
    # SageMaker-based privilege escalation patterns
    "PassRole+SageMakerCreateNotebookInstance": {
        "iam:PassRole",
        "sagemaker:CreateNotebookInstance",
    },
    "PassRole+SageMakerCreateTrainingJob": {
        "iam:PassRole",
        "sagemaker:CreateTrainingJob",
    },
    "PassRole+SageMakerCreateProcessingJob": {
        "iam:PassRole",
        "sagemaker:CreateProcessingJob",
    },
    # Prerequisite: Existing SageMaker notebook instance with admin role
    "SageMakerCreatePresignedNotebookInstanceUrl": {
        "sagemaker:CreatePresignedNotebookInstanceUrl",
    },
    # Prerequisite: Existing SageMaker notebook instance with admin role
    "SageMakerNotebookLifecycleConfig": {
        "sagemaker:CreateNotebookInstanceLifecycleConfig",
        "sagemaker:StopNotebookInstance",
        "sagemaker:UpdateNotebookInstance",
        "sagemaker:StartNotebookInstance",
    },
    # SSM-based privilege escalation patterns
    # Prerequisite: Running EC2 with SSM agent and admin instance profile
    "SSMStartSession": {"ssm:StartSession"},
    # Prerequisite: Running EC2 with SSM agent and admin instance profile
    "SSMSendCommand": {"ssm:SendCommand"},
    # AppRunner-based privilege escalation patterns
    "PassRole+AppRunnerCreateService": {
        "iam:PassRole",
        "apprunner:CreateService",
    },
    # Prerequisite: Existing App Runner service with admin role
    "AppRunnerUpdateService": {"apprunner:UpdateService"},
    # Bedrock AgentCore privilege escalation patterns
    "PassRole+AgentCoreCreateInterpreter+InvokeInterpreter": {
        "iam:PassRole",
        "bedrock-agentcore:CreateCodeInterpreter",
        "bedrock-agentcore:InvokeCodeInterpreter",
    },
    # Prerequisite: Existing Bedrock code interpreter with admin role
    "AgentCoreSessionInvoke": {
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
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
