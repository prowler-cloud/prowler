import yaml from "js-yaml";

import { mutedFindingsConfigFormSchema } from "@/types/formSchemas";

/**
 * Validates if a string is valid YAML and returns detailed validation result
 */
export const validateYaml = (
  val: string,
): { isValid: boolean; error?: string } => {
  try {
    const parsed = yaml.load(val);

    if (parsed === null || parsed === undefined) {
      return { isValid: false, error: "YAML content is empty or null" };
    }

    if (typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        isValid: false,
        error: "YAML must be an object, not an array or primitive value",
      };
    }

    return { isValid: true };
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown YAML parsing error";
    return { isValid: false, error: errorMessage };
  }
};

/**
 * Validates if a YAML string contains a valid mutelist structure and returns detailed validation result
 */
export const validateMutelistYaml = (
  val: string,
): { isValid: boolean; error?: string } => {
  try {
    const parsed = yaml.load(val) as Record<string, any>;

    // yaml.load() can return null, arrays, or primitives
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { isValid: false, error: "YAML content must be a valid object" };
    }

    // Verify structure using optional chaining
    const accounts = parsed.Mutelist?.Accounts;
    if (!accounts || typeof accounts !== "object" || Array.isArray(accounts)) {
      return {
        isValid: false,
        error: "Missing or invalid 'Mutelist.Accounts' structure",
      };
    }

    const accountKeys = Object.keys(accounts);
    if (accountKeys.length === 0) {
      return {
        isValid: false,
        error: "At least one account must be defined in 'Mutelist.Accounts'",
      };
    }

    for (const accountKey of accountKeys) {
      const account = accounts[accountKey];
      if (!account || typeof account !== "object" || Array.isArray(account)) {
        return {
          isValid: false,
          error: `Account '${accountKey}' must be a valid object`,
        };
      }

      const checks = account.Checks;
      if (!checks || typeof checks !== "object" || Array.isArray(checks)) {
        return {
          isValid: false,
          error: `Missing or invalid 'Checks' structure for account '${accountKey}'`,
        };
      }

      const checkKeys = Object.keys(checks);
      if (checkKeys.length === 0) {
        return {
          isValid: false,
          error: `At least one check must be defined for account '${accountKey}'`,
        };
      }

      for (const checkKey of checkKeys) {
        const check = checks[checkKey];
        if (!check || typeof check !== "object" || Array.isArray(check)) {
          return {
            isValid: false,
            error: `Check '${checkKey}' in account '${accountKey}' must be a valid object`,
          };
        }

        const { Regions: regions, Resources: resources } = check;
        if (!Array.isArray(regions)) {
          return {
            isValid: false,
            error: `'Regions' must be an array in check '${checkKey}' for account '${accountKey}'`,
          };
        }
        if (!Array.isArray(resources)) {
          return {
            isValid: false,
            error: `'Resources' must be an array in check '${checkKey}' for account '${accountKey}'`,
          };
        }
      }
    }

    return { isValid: true };
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error
        ? error.message
        : "Unknown error validating mutelist structure";
    return { isValid: false, error: errorMessage };
  }
};

/**
 * Validates YAML using the mutelist schema and returns detailed error information
 */
export const parseYamlValidation = (
  yamlString: string,
): { isValid: boolean; error?: string } => {
  try {
    const result = mutedFindingsConfigFormSchema.safeParse({
      configuration: yamlString,
    });

    if (result.success) {
      return { isValid: true };
    } else {
      const firstError = result.error.issues[0];
      return {
        isValid: false,
        error: firstError.message,
      };
    }
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown validation error";
    return { isValid: false, error: errorMessage };
  }
};

/**
 * Converts a configuration (string or object) to YAML format
 */
export const convertToYaml = (config: string | object): string => {
  if (!config) return "";

  try {
    // If it's already an object, convert directly to YAML
    if (typeof config === "object") {
      return yaml.dump(config, { indent: 2 });
    }

    // If it's a string, try to parse as JSON first
    try {
      const jsonConfig = JSON.parse(config);
      return yaml.dump(jsonConfig, { indent: 2 });
    } catch {
      // If it's not JSON, assume it's already YAML
      return config;
    }
  } catch (_error) {
    return config.toString();
  }
};

export const defaultMutedFindingsConfig = `# If no Mutelist is provided, a default one is used for AWS accounts to exclude certain predefined resources.

# The default AWS Mutelist is defined here: https://github.com/prowler-cloud/prowler/blob/master/prowler/config/aws_mutelist.yaml

Mutelist:
  Accounts:
    "*":
      ########################### AWS CONTROL TOWER ###########################
      ### The following entries includes all resources created by AWS Control Tower when setting up a landing zone ###
      # https://docs.aws.amazon.com/controltower/latest/userguide/shared-account-resources.html #
      Checks:
        "awslambda_function_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-NotificationForwarder"
          Description: "Checks from AWS lambda functions muted by default"
        "cloudformation_stack*":
          Regions:
            - "*"
          Resources:
            - "StackSet-AWSControlTowerGuardrailAWS-*"
            - "StackSet-AWSControlTowerBP-*"
            - "StackSet-AWSControlTowerSecurityResources-*"
            - "StackSet-AWSControlTowerLoggingResources-*"
            - "StackSet-AWSControlTowerExecutionRole-*"
            - "AWSControlTowerBP-BASELINE-CLOUDTRAIL-MASTER*"
            - "AWSControlTowerBP-BASELINE-CONFIG-MASTER*"
            - "StackSet-AWSControlTower*"
            - "CLOUDTRAIL-ENABLED-ON-SHARED-ACCOUNTS-*"
            - "AFT-Backend*"
        "cloudtrail_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-BaselineCloudTrail"
        "cloudwatch_log_group_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower/CloudTrailLogs"
            - "/aws/lambda/aws-controltower-NotificationForwarder"
            - "StackSet-AWSControlTowerBP-*"
        "iam_inline_policy_no_administrative_privileges":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-ForwardSnsNotificationRole/sns"
            - "aws-controltower-AuditAdministratorRole/AssumeRole-aws-controltower-AuditAdministratorRole"
            - "aws-controltower-AuditReadOnlyRole/AssumeRole-aws-controltower-AuditReadOnlyRole"
        "iam.*policy_*":
          Regions:
            - "*"
          Resources:
            - "AWSControlTowerAccountServiceRolePolicy"
            - "AWSControlTowerServiceRolePolicy"
            - "AWSControlTowerStackSetRolePolicy"
            - "AWSControlTowerAdminPolicy"
            - "AWSLoadBalancerControllerIAMPolicy"
            - "AWSControlTowerCloudTrailRolePolicy"
        "iam_role_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-AdministratorExecutionRole"
            - "aws-controltower-AuditAdministratorRole"
            - "aws-controltower-AuditReadOnlyRole"
            - "aws-controltower-CloudWatchLogsRole"
            - "aws-controltower-ConfigRecorderRole"
            - "aws-controltower-ForwardSnsNotificationRole"
            - "aws-controltower-ReadOnlyExecutionRole"
            - "AWSControlTower_VPCFlowLogsRole"
            - "AWSControlTowerExecution"
            - "AWSControlTowerCloudTrailRole"
            - "AWSControlTowerConfigAggregatorRoleForOrganizations"
            - "AWSControlTowerStackSetRole"
            - "AWSControlTowerAdmin"
            - "AWSAFTAdmin"
            - "AWSAFTExecution"
            - "AWSAFTService"
        "s3_bucket_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-logs-*"
            - "aws-controltower-s3-access-logs-*"
        "sns_*":
          Regions:
            - "*"
          Resources:
            - "aws-controltower-AggregateSecurityNotifications"
            - "aws-controltower-AllConfigNotifications"
            - "aws-controltower-SecurityNotifications"
        "vpc_*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "Name=aws-controltower-VPC"`;
