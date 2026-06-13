# Example Solution:  Serverless Organizational Prowler Deployment with SecurityHub

Deploys [Prowler](https://github.com/prowler-cloud/prowler) with AWS Fargate to assess all Accounts in an AWS Organization on a schedule, and sends the results to Security Hub.

## Context
Originally based on [org-multi-account](https://github.com/prowler-cloud/prowler/tree/master/util/org-multi-account), but changed in the following ways:

 - No HTML reports and no S3 buckets
 - Findings sent directly to Security Hub using the native integration
 - AWS Fargate Task with EventBridge Rule instead of EC2 instance with cronjob
 - Based on amazonlinux:2022 to leverage "wait -n" for improved parallelization as new jobs are launched as one finishes

## Architecture Explanation

The solution is designed to be very simple. Prowler is run via an ECS Task definition that launches a single Fargate container. This Task Definition is executed on a schedule using an EventBridge Rule.

## Prerequisites

This solution assumes that you have a VPC architecture with two redundant subnets that can reach the AWS API endpoints (e.g. PrivateLink, NAT Gateway, etc.).

## CloudFormation Templates

 ### CF-Prowler-IAM.yml
Creates the following IAM Roles:

 1. **ECSExecutionRole**: Required for the Task Definition to be able to fetch the container image from ECR and launch the container.
 2. **ProwlerTaskRole**: Role that the container itself runs with. It allows it to assume the ProwlerCrossAccountRole.
 3. **ECSEventRoleName**: Required for the EventBridge Rule to execute the Task Definition.

### CF-Prowler-ECS.yml
Creates the following resources:

 1. **ProwlerECSCluster**: Cluster to be used to execute the Task Definition.
 2. **ProwlerECSCloudWatchLogsGroup**: Log group for the Prowler container logs. This is required because it's the only log driver supported by Fargate. The Prowler executable logs are suppressed to prevent unnecessary logs, but error logs are kept for debugging.
 3. **ProwlerECSTaskDefinition**: Task Definition for the Fargate container. CPU and memory can be increased as needed. In my experience, 1 CPU per parallel Prowler job is ideal, but further performance testing may be required to find the optimal configuration for a specific organization. Enabling container insights helps a lot with this.
 4. **ProwlerSecurityGroup**: Security Group for the container. It only allows TCP 443 outbound, as it is the only port needed for awscli.
 5. **ProwlerTaskScheduler**: EventBridge Rule that schedules the execution of the Task Definition. The cron expression is specified as a CloudFormation template parameter.

### CF-Prowler-CrossAccountRole.yml
Creates the cross account IAM Role required for Prowler to run. Deploy it as StackSet in every account in the AWS Organization.

## Docker Container

### Dockerfile
The Dockerfile does the following:
 1. Uses amazonlinux:2022 as a base.
 2. Downloads required dependencies.
 3. Copies the .awsvariables and run-prowler-securityhub.sh files into the root.
 4. Downloads the specified version of Prowler as recommended in the release notes.
 5. Assigns permissions to a lower privileged user and then drops to it.
 6. Runs the script.

### .awsvariables
The .awsvariables file is used to pass required configuration to the script:

 1. **ROLE**: The cross account Role to be assumed for the Prowler assessments.
 2. **PARALLEL_ACCOUNTS**: The number of accounts to be scanned in parallel.
 3. **REGION**: Region where Prowler will run its assessments.

### run-prowler-securityhub.sh
The script gets the list of accounts in AWS Organizations, and then executes Prowler as a job for each account, up to PARALLEL_ACCOUNT accounts at the same time.
The logs that are generated and sent to Cloudwatch are error logs, and assessment start and finish logs.

## Instructions
 1. Create a Private ECR Repository in the account that will host the Prowler container. The Audit account is recommended, but any account can be used.
 2. Configure the .awsvariables file. Note the ROLE name chosen as it will be the CrossAccountRole.
 3. Follow the steps from "View Push Commands" to build and upload the container image. Substitute step 2 with the build command provided in the Dockerfile. You need to have Docker and AWS CLI installed, and use the cli to login to the account first.  After upload note the Image URI, as it is required for the CF-Prowler-ECS template. Ensure that you pay attention to the architecture while performing the docker build command. A common mistake is not specifying the architecture and then building on Apple silicon. Your task will fail with  *exec /home/prowler/.local/bin/prowler: exec format error*. 
 4. Make sure SecurityHub is enabled in every account in AWS Organizations, and that the SecurityHub integration is enabled as explained in [Prowler - Security Hub Integration](https://github.com/prowler-cloud/prowler#security-hub-integration)
 5. Deploy **CF-Prowler-CrossAccountRole.yml** in the Master Account as a single stack. You will have to choose the CrossAccountRole name (ProwlerXA-Role by default) and the ProwlerTaskRoleName (ProwlerECSTask-Role by default)
 6. Deploy **CF-Prowler-CrossAccountRole.yml** in every Member Account as a StackSet. Choose the same CrossAccountName and ProwlerTaskRoleName as the previous step.
 7. Deploy **CF-Prowler-IAM.yml** in the account that will host the Prowler container (the same from step 1).  The following template parameters must be provided:
    - **ProwlerCrossAccountRoleName**: Name of the from CF-Prowler-CrossAccountRole (default ProwlerXA-Role).
    - **ECSExecutionRoleName**: Name for the ECS Task Execution Role (default ECSTaskExecution-Role).
    - **ProwlerTaskRoleName**: Name for the ECS Prowler Task Role (default ProwlerECSTask-Role).
    - **ECSEventRoleName**: Name for the Eventbridge Task Role (default ProwlerEvents-Role).
 8. Deploy **CF-Prowler-ECS.yml** in the account that will host the Prowler container (the same from step 1).  The following template parameters must be provided:
	- **ProwlerClusterName**: Name for the ECS Cluster (default ProwlerCluster)
	- **ProwlerContainerName**: Name for the Prowler container (default prowler)
	- **ProwlerContainerInfo**: ECR URI from step 1.
	- **ProwlerECSLogGroupName**: CloudWatch Log Group name (default /aws/ecs/SecurityHub-Prowler)
	- **SecurityGroupVPCId**: VPC ID for the VPC where the container will run.
	- **ProwlerScheduledSubnet1 and 2**: Subnets IDs from the VPC specified. Choose private subnets if possible.
	- **ECSExecutionRole**: ECS Execution Task Role ARN from CF-Prowler-IAM outputs.
	- **ProwlerTaskRole**: Prowler ECS Task Role ARN from CF-Prowler-IAM outputs.
	- **ECSEventRole**: Eventbridge Task Role ARN from CF-Prowler-IAM outputs.
	- **CronExpression**: Valid Cron Expression for the scheduling of the Task Definition.
 9. Verify that Prowler runs correctly by checking the CloudWatch logs after the scheduled task is executed.

---
## Troubleshooting

If you permission find errors in the CloudWatch logs, the culprit might be a [Service Control Policy (SCP)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html). You will need to exclude the Prowler Cross Account Role from those SCPs.

---
## Upgrading Prowler

Prowler version is controlled by the PROWLERVER argument in the Dockerfile, change it to the desired version and follow the ECR Push Commands to update the container image.
Old images can be deleted from the ECR Repository after the new image is confirmed to work. They will show as "untagged" as only one image can hold the "latest" tag.
