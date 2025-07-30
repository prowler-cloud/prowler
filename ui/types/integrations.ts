import { z } from "zod";

// Integration types
export type IntegrationType =
  | "amazon_s3"
  | "aws_security_hub"
  | "jira"
  | "slack";

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
      output_directory?: string; // Changed from path to output_directory
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

export interface IntegrationsApiResponse {
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
  data: IntegrationProps[];
  included?: Array<{
    type: string;
    id: string;
    attributes: any;
    relationships?: any;
  }>;
  meta: {
    pagination: { page: number; pages: number; count: number };
    version: string;
  };
}

// S3 Integration specific types
export interface S3IntegrationConfiguration {
  bucket_name: string;
  output_directory: string; // Changed from path to output_directory
  credentials: {
    aws_access_key_id: string;
    aws_secret_access_key: string;
    aws_session_token?: string;
    role_arn?: string; // IAM Role fields are optional
    external_id?: string;
    role_session_name?: string;
    session_duration?: number;
  };
}

export const s3IntegrationFormSchema = z
  .object({
    integration_type: z.literal("amazon_s3"),
    bucket_name: z.string().min(1, "Bucket name is required"),
    output_directory: z.string().min(1, "Output directory is required"),
    providers: z
      .array(z.string())
      .min(1, "At least one provider must be selected"),
    // AWS Credentials fields compatible with AWSCredentialsRole
    credentials_type: z
      .enum(["aws-sdk-default", "access-secret-key"])
      .default("aws-sdk-default"),
    aws_access_key_id: z.string().optional(),
    aws_secret_access_key: z.string().optional(),
    aws_session_token: z.string().optional(),
    // IAM Role fields
    role_arn: z.string().optional(),
    external_id: z.string().optional(),
    role_session_name: z.string().optional(),
    session_duration: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    // If using access-secret-key, require AWS credentials
    if (data.credentials_type === "access-secret-key") {
      if (!data.aws_access_key_id) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "AWS Access Key ID is required when using access and secret key",
          path: ["aws_access_key_id"],
        });
      }
      if (!data.aws_secret_access_key) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "AWS Secret Access Key is required when using access and secret key",
          path: ["aws_secret_access_key"],
        });
      }
    }

    // If role_arn is provided, external_id is required
    if (data.role_arn && data.role_arn.trim() !== "") {
      if (!data.external_id || data.external_id.trim() === "") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "External ID is required when using Role ARN",
          path: ["external_id"],
        });
      }
    }
  });

export const editS3IntegrationFormSchema = z
  .object({
    integration_type: z.literal("amazon_s3"),
    bucket_name: z.string().min(1, "Bucket name is required").optional(),
    output_directory: z
      .string()
      .min(1, "Output directory is required")
      .optional(),
    providers: z
      .array(z.string())
      .min(1, "At least one provider must be selected")
      .optional(),
    credentials_type: z
      .enum(["aws-sdk-default", "access-secret-key"])
      .optional(),
    aws_access_key_id: z.string().optional(),
    aws_secret_access_key: z.string().optional(),
    aws_session_token: z.string().optional(),
    role_arn: z.string().optional(),
    external_id: z.string().optional(),
    role_session_name: z.string().optional(),
    session_duration: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    // If using access-secret-key, and credentials are provided, require both
    if (data.credentials_type === "access-secret-key") {
      const hasAccessKey = !!data.aws_access_key_id;
      const hasSecretKey = !!data.aws_secret_access_key;

      if (hasAccessKey && !hasSecretKey) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "AWS Secret Access Key is required when providing Access Key ID",
          path: ["aws_secret_access_key"],
        });
      }

      if (hasSecretKey && !hasAccessKey) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "AWS Access Key ID is required when providing Secret Access Key",
          path: ["aws_access_key_id"],
        });
      }
    }
  });
