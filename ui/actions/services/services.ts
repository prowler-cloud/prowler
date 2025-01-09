"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { parse } from "path";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

export const getServices = async ({}) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const servicesToFetch = [
    { id: "accessanalyzer", alias: "IAM Access Analyzer" },
    { id: "account", alias: "AWS Account" },
    { id: "acm", alias: "AWS Certificate Manager" },
    { id: "apigateway", alias: "Amazon API Gateway" },
    { id: "apigatewayv2", alias: "Amazon API Gateway V2" },
    { id: "athena", alias: "Amazon Athena" },
    { id: "autoscaling", alias: "Amazon EC2 Auto Scaling" },
    { id: "awslambda", alias: "AWS Lambda" },
    { id: "backup", alias: "AWS Backup" },
    { id: "cloudformation", alias: "AWS CloudFormation" },
    { id: "cloudfront", alias: "Amazon CloudFront" },
    { id: "cloudtrail", alias: "AWS CloudTrail" },
    { id: "cloudwatch", alias: "Amazon CloudWatch" },
    { id: "codeartifact", alias: "AWS CodeArtifact" },
    { id: "codebuild", alias: "AWS CodeBuild" },
    { id: "config", alias: "AWS Config" },
    { id: "dlm", alias: "Amazon Data Lifecycle Manager" },
    { id: "drs", alias: "AWS Data Replication Service" },
    { id: "dynamodb", alias: "Amazon DynamoDB" },
    { id: "ec2", alias: "Amazon EC2" },
    { id: "ecr", alias: "Amazon ECR" },
    { id: "ecs", alias: "Amazon ECS" },
    { id: "efs", alias: "Amazon EFS" },
    { id: "eks", alias: "Amazon EKS" },
    { id: "elasticache", alias: "Amazon ElastiCache" },
    { id: "elb", alias: "Elastic Load Balancing" },
    { id: "elbv2", alias: "Elastic Load Balancing v2" },
    { id: "emr", alias: "Amazon EMR" },
    { id: "fms", alias: "AWS Firewall Manager" },
    { id: "glacier", alias: "Amazon Glacier" },
    { id: "glue", alias: "AWS Glue" },
    { id: "guardduty", alias: "Amazon GuardDuty" },
    { id: "iam", alias: "AWS IAM" },
    { id: "inspector2", alias: "Amazon Inspector" },
    { id: "kms", alias: "AWS KMS" },
    { id: "macie", alias: "Amazon Macie" },
    { id: "networkfirewall", alias: "AWS Network Firewall" },
    { id: "organizations", alias: "AWS Organizations" },
    { id: "rds", alias: "Amazon RDS" },
    { id: "resourceexplorer2", alias: "AWS Resource Groups" },
    { id: "route53", alias: "Amazon Route 53" },
    { id: "s3", alias: "Amazon S3" },
    { id: "secretsmanager", alias: "AWS Secrets Manager" },
    { id: "securityhub", alias: "AWS Security Hub" },
    { id: "sns", alias: "Amazon SNS" },
    { id: "sqs", alias: "Amazon SQS" },
    { id: "ssm", alias: "AWS Systems Manager" },
    { id: "ssmincidents", alias: "AWS Systems Manager Incident Manager" },
    { id: "trustedadvisor", alias: "AWS Trusted Advisor" },
    { id: "vpc", alias: "Amazon VPC" },
    { id: "wafv2", alias: "AWS WAF" },
    { id: "wellarchitected", alias: "AWS Well-Architected Tool" },
  ];

  const parsedData = [];

  for (const service of servicesToFetch) {
    const url = new URL(`${keyServer}/findings`);
    url.searchParams.append("filter[service]", service.id);
    url.searchParams.append("filter[status]", "FAIL");

    try {
      const response = await fetch(url.toString(), {
        headers: {
          Accept: "application/vnd.api+json",
          Authorization: `Bearer ${session?.accessToken}`,
        },
      });

      const data = await response.json();
      const failFindings = data.meta.pagination.count;

      parsedData.push({
        service_id: service.id,
        service_alias: service.alias,
        fail_findings: failFindings,
      });
    } catch (error) {
      console.error(`Error fetching data for service ${service.id}:`, error);
    }
  }

  revalidatePath("/services");
  return parsedData;
};
