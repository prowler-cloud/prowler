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
# - https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation (AWS Bedrock AgentCore)

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
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
    },
    # Prerequisite: Existing Bedrock code interpreter with admin role
    "AgentCoreSessionInvoke": {
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
    },
    # Prerequisite: Existing AgentCore Runtime or Harness with admin execution role.
    # InvokeAgentRuntimeCommand runs shell commands as root inside the microVM and
    # reads the execution role credentials from MMDS, bypassing the agent and guardrails.
    "AgentCoreInvokeRuntimeCommand": {
        "bedrock-agentcore:InvokeAgentRuntimeCommand",
    },
    "PassRole+AgentCoreCreateRuntime+InvokeRuntimeCommand": {
        "iam:PassRole",
        "bedrock-agentcore:CreateAgentRuntime",
        "bedrock-agentcore:CreateAgentRuntimeEndpoint",
        "bedrock-agentcore:CreateWorkloadIdentity",
        "bedrock-agentcore:InvokeAgentRuntimeCommand",
    },
    "PassRole+AgentCoreCreateHarness+InvokeRuntimeCommand": {
        "iam:PassRole",
        "bedrock-agentcore:CreateHarness",
        "bedrock-agentcore:CreateAgentRuntime",
        "bedrock-agentcore:CreateAgentRuntimeEndpoint",
        "bedrock-agentcore:CreateWorkloadIdentity",
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:InvokeAgentRuntimeCommand",
    },
    # Prerequisite: Existing AgentCore Custom Browser with admin execution role.
    # A remote CDP driver on the browser session reads the role credentials from MMDS.
    "AgentCoreBrowserSessionConnect": {
        "bedrock-agentcore:StartBrowserSession",
        "bedrock-agentcore:ConnectBrowserAutomationStream",
    },
    "PassRole+AgentCoreCreateBrowser+ConnectBrowser": {
        "iam:PassRole",
        "bedrock-agentcore:CreateBrowser",
        "bedrock-agentcore:StartBrowserSession",
        "bedrock-agentcore:ConnectBrowserAutomationStream",
    },
    # Batch-based privilege escalation patterns (pathfinding.cloud BATCH-001/002)
    "PassRole+BatchRegisterJobDef+SubmitJob": {
        "iam:PassRole",
        "batch:RegisterJobDefinition",
        "batch:SubmitJob",
    },
    # Prerequisite: Existing Batch job definition with admin role
    "BatchSubmitJob": {"batch:SubmitJob"},
    # Braket-based privilege escalation patterns (pathfinding.cloud BRAKET-001)
    "PassRole+BraketCreateJob": {
        "iam:PassRole",
        "braket:CreateJob",
    },
    # CodeDeploy-based privilege escalation patterns (pathfinding.cloud CODEDEPLOY-001)
    # Prerequisite: Existing CodeDeploy application and deployment group with admin role
    "CodeDeployCreateDeployment": {
        "codedeploy:CreateDeployment",
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetDeploymentConfig",
    },
    # Cognito Identity-based privilege escalation patterns (pathfinding.cloud COGNITOIDENTITY-001)
    "PassRole+CognitoSetIdentityPoolRoles": {
        "iam:PassRole",
        "cognito-identity:SetIdentityPoolRoles",
    },
    # ECS StartTask on an existing cluster (pathfinding.cloud ECS-009)
    "PassRole+ECSStartTaskExistingCluster": {
        "iam:PassRole",
        "ecs:StartTask",
    },
    # EMR-based privilege escalation patterns (pathfinding.cloud EMR-001)
    "PassRole+EMRRunJobFlow": {
        "iam:PassRole",
        "elasticmapreduce:RunJobFlow",
    },
    # EMR Serverless-based privilege escalation patterns (pathfinding.cloud EMRSERVERLESS-001)
    "PassRole+EMRServerlessCreateApp+StartJobRun": {
        "iam:PassRole",
        "emr-serverless:CreateApplication",
        "emr-serverless:StartJobRun",
    },
    # GameLift-based privilege escalation patterns (pathfinding.cloud GAMELIFT-001)
    "PassRole+GameLiftCreateBuild+CreateFleet": {
        "iam:PassRole",
        "gamelift:CreateBuild",
        "gamelift:CreateFleet",
        "gamelift:RequestUploadCredentials",
    },
    # Glue interactive session-based privilege escalation patterns (pathfinding.cloud GLUE-007)
    "PassRole+GlueCreateSession+RunStatement": {
        "iam:PassRole",
        "glue:CreateSession",
        "glue:RunStatement",
    },
    # EC2 Image Builder-based privilege escalation patterns (pathfinding.cloud IMAGEBUILDER-001)
    "PassRole+ImageBuilderCreateComponent+CreateImage": {
        "iam:PassRole",
        "imagebuilder:CreateComponent",
        "imagebuilder:CreateImageRecipe",
        "imagebuilder:CreateInfrastructureConfiguration",
        "imagebuilder:CreateImage",
    },
    # Kinesis Data Analytics-based privilege escalation patterns (pathfinding.cloud KINESISANALYTICS-001)
    "PassRole+KinesisAnalyticsCreateApp+StartApp": {
        "iam:PassRole",
        "kinesisanalytics:CreateApplication",
        "kinesisanalytics:StartApplication",
    },
    # HealthOmics-based privilege escalation patterns (pathfinding.cloud OMICS-001)
    "PassRole+OmicsCreateWorkflow+StartRun": {
        "iam:PassRole",
        "omics:CreateWorkflow",
        "omics:StartRun",
        "s3:GetObject",
    },
    # EventBridge Scheduler-based privilege escalation patterns (pathfinding.cloud SCHEDULER-001)
    "PassRole+SchedulerCreateSchedule": {
        "iam:PassRole",
        "scheduler:CreateSchedule",
    },
    # SSM Automation document-based privilege escalation patterns (pathfinding.cloud SSM-003)
    "PassRole+SSMCreateDocument+StartAutomation": {
        "iam:PassRole",
        "ssm:CreateDocument",
        "ssm:StartAutomationExecution",
    },
    # Step Functions-based privilege escalation patterns (pathfinding.cloud STEPFUNCTIONS-001)
    "PassRole+StepFunctionsCreateStateMachine+StartExecution": {
        "iam:PassRole",
        "states:CreateStateMachine",
        "states:StartExecution",
    },
    # Prerequisite: Existing Step Functions state machine with admin role (pathfinding.cloud STEPFUNCTIONS-002)
    "StepFunctionsUpdateStateMachine+StartExecution": {
        "states:UpdateStateMachine",
        "states:StartExecution",
    },
    # IAM permissions boundary removal self-escalation (pathfinding.cloud IAM-022)
    "iam:DeleteUserPermissionsBoundary": {"iam:DeleteUserPermissionsBoundary"},
    # Role permissions boundary removal plus role assumption (pathfinding.cloud IAM-023)
    "AssumeRole+DeleteRolePermissionsBoundary": {
        "sts:AssumeRole",
        "iam:DeleteRolePermissionsBoundary",
    },
    # IAM Identity Center (SSO)-based privilege escalation patterns (pathfinding.cloud SSO-001)
    "SSOCreatePermissionSet+CreateAccountAssignment+AttachManagedPolicy": {
        "sso:CreatePermissionSet",
        "sso:CreateAccountAssignment",
        "sso:AttachManagedPolicyToPermissionSet",
    },
    # Prerequisite: Existing permission set assigned to the attacker (pathfinding.cloud SSO-002)
    "sso:AttachManagedPolicyToPermissionSet": {
        "sso:AttachManagedPolicyToPermissionSet"
    },
    # Prerequisite: Existing permission set assigned to the attacker (pathfinding.cloud SSO-003)
    "sso:PutInlinePolicyToPermissionSet": {"sso:PutInlinePolicyToPermissionSet"},
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
