import { z } from "zod";

export type IntegrationType = "amazon_s3" | "aws_security_hub" | "jira";

export interface IntegrationProps {
  type: "integrations";
  id: string;
  attributes: {
    inserted_at: string;
    updated_at: string;
    enabled: boolean;
    connected: boolean;
    connection_last_checked_at: string | null;
    integration_type: IntegrationType;
    configuration: {
      bucket_name?: string;
      output_directory?: string;
      credentials?: {
        aws_access_key_id?: string;
        aws_secret_access_key?: string;
        aws_session_token?: string;
        role_arn?: string;
        external_id?: string;
        role_session_name?: string;
        session_duration?: number;
      };
      [key: string]: any;
    };
    url?: string;
  };
  relationships?: { providers?: { data: { type: "providers"; id: string }[] } };
  links: { self: string };
}

// Shared AWS credential fields schema
const awsCredentialFields = {
  credentials_type: z.enum(["aws-sdk-default", "access-secret-key"]),
  aws_access_key_id: z.string().optional(),
  aws_secret_access_key: z.string().optional(),
  aws_session_token: z.string().optional(),
  role_arn: z.string().optional(),
  external_id: z.string().optional(),
  role_session_name: z.string().optional(),
  session_duration: z.string().optional(),
  show_role_section: z.boolean().optional(),
};

// Shared validation helper for AWS credentials (create mode)
const validateAwsCredentialsCreate = (
  data: any,
  ctx: z.RefinementCtx,
  requireCredentials: boolean = true,
) => {
  if (data.credentials_type === "access-secret-key" && requireCredentials) {
    if (!data.aws_access_key_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS Access Key ID is required when using access and secret key",
        path: ["aws_access_key_id"],
      });
    }
    if (!data.aws_secret_access_key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS Secret Access Key is required when using access and secret key",
        path: ["aws_secret_access_key"],
      });
    }
  }
};

// Shared validation helper for AWS credentials (edit mode)
const validateAwsCredentialsEdit = (data: any, ctx: z.RefinementCtx) => {
  if (data.credentials_type === "access-secret-key") {
    const hasAccessKey = !!data.aws_access_key_id;
    const hasSecretKey = !!data.aws_secret_access_key;

    if (hasAccessKey && !hasSecretKey) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS Secret Access Key is required when providing Access Key ID",
        path: ["aws_secret_access_key"],
      });
    }

    if (hasSecretKey && !hasAccessKey) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS Access Key ID is required when providing Secret Access Key",
        path: ["aws_access_key_id"],
      });
    }
  }
};

// Shared validation helper for IAM Role fields
const validateIamRole = (
  data: any,
  ctx: z.RefinementCtx,
  checkShowSection: boolean = true,
) => {
  const shouldValidate = checkShowSection ? data.show_role_section === true : true;
  
  if (shouldValidate && data.role_arn) {
    if (data.role_arn.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Role ARN is required",
        path: ["role_arn"],
      });
    } else if (!data.external_id || data.external_id.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "External ID is required when using Role ARN",
        path: ["external_id"],
      });
    }
  }

  if (checkShowSection && data.show_role_section === true) {
    if (!data.role_arn || data.role_arn.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Role ARN is required",
        path: ["role_arn"],
      });
    }
    if (!data.external_id || data.external_id.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "External ID is required",
        path: ["external_id"],
      });
    }
  }
};

// S3 Integration Schemas
const baseS3IntegrationSchema = z.object({
  integration_type: z.literal("amazon_s3"),
  bucket_name: z.string().min(1, "Bucket name is required"),
  output_directory: z.string().min(1, "Output directory is required"),
  providers: z.array(z.string()).optional(),
  enabled: z.boolean().optional(),
  ...awsCredentialFields,
});

export const s3IntegrationFormSchema = baseS3IntegrationSchema
  .extend({
    enabled: z.boolean().default(true),
    credentials_type: z
      .enum(["aws-sdk-default", "access-secret-key"])
      .default("aws-sdk-default"),
  })
  .superRefine((data, ctx) => {
    validateAwsCredentialsCreate(data, ctx);
    validateIamRole(data, ctx);
  });

export const editS3IntegrationFormSchema = baseS3IntegrationSchema
  .extend({
    bucket_name: z.string().min(1, "Bucket name is required").optional(),
    output_directory: z.string().min(1, "Output directory is required").optional(),
    providers: z.array(z.string()).optional(),
    credentials_type: z.enum(["aws-sdk-default", "access-secret-key"]).optional(),
  })
  .superRefine((data, ctx) => {
    validateAwsCredentialsEdit(data, ctx);
    validateIamRole(data, ctx);
  });

// Security Hub Integration Schemas
const baseSecurityHubIntegrationSchema = z.object({
  integration_type: z.literal("aws_security_hub"),
  provider_id: z.string().min(1, "AWS Provider is required"),
  send_only_fails: z.boolean().optional(),
  archive_previous_findings: z.boolean().optional(),
  use_custom_credentials: z.boolean().optional(),
  enabled: z.boolean().optional(),
  ...awsCredentialFields,
});

export const securityHubIntegrationFormSchema = baseSecurityHubIntegrationSchema
  .extend({
    enabled: z.boolean().default(true),
    send_only_fails: z.boolean().default(true),
    archive_previous_findings: z.boolean().default(false),
    use_custom_credentials: z.boolean().default(false),
    credentials_type: z
      .enum(["aws-sdk-default", "access-secret-key"])
      .default("aws-sdk-default"),
  })
  .superRefine((data, ctx) => {
    if (data.use_custom_credentials) {
      validateAwsCredentialsCreate(data, ctx);
      validateIamRole(data, ctx);
    }
    // Always validate role if role_arn is provided
    if (!data.use_custom_credentials && data.role_arn) {
      validateIamRole(data, ctx, false);
    }
  });

export const editSecurityHubIntegrationFormSchema = baseSecurityHubIntegrationSchema
  .extend({
    provider_id: z.string().optional(),
    send_only_fails: z.boolean().optional(),
    archive_previous_findings: z.boolean().optional(),
    use_custom_credentials: z.boolean().optional(),
    credentials_type: z.enum(["aws-sdk-default", "access-secret-key"]).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.use_custom_credentials !== false) {
      validateAwsCredentialsEdit(data, ctx);
    }
    // Always validate role if role_arn is provided
    validateIamRole(data, ctx, false);
  });