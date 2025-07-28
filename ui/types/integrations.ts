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
  relationships?: {
    providers?: {
      data: {
        type: "providers";
        id: string;
      }[];
    };
  };
  links: {
    self: string;
  };
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
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
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
    // Static credentials are always required
    aws_access_key_id: z.string().min(1, "AWS Access Key ID is required"),
    aws_secret_access_key: z
      .string()
      .min(1, "AWS Secret Access Key is required"),
    aws_session_token: z.string().optional(),
    // IAM Role fields
    use_iam_role: z.boolean().optional(), // Flag to indicate if IAM role should be used
    role_arn: z.string().optional(),
    external_id: z.string().optional(),
    role_session_name: z.string().optional(),
    session_duration: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    // If IAM role is enabled, require role_arn and external_id
    if (data.use_iam_role) {
      if (!data.role_arn) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Role ARN is required when using IAM Role",
          path: ["role_arn"],
        });
      }
      if (!data.external_id) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "External ID is required when using IAM Role",
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
    aws_access_key_id: z.string().optional(),
    aws_secret_access_key: z.string().optional(),
    aws_session_token: z.string().optional(),
    use_iam_role: z.boolean().optional(),
    role_arn: z.string().optional(),
    external_id: z.string().optional(),
    role_session_name: z.string().optional(),
    session_duration: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    // If IAM role is enabled, require role_arn and external_id
    if (data.use_iam_role) {
      if (!data.role_arn) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Role ARN is required when using IAM Role",
          path: ["role_arn"],
        });
      }
      if (!data.external_id) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "External ID is required when using IAM Role",
          path: ["external_id"],
        });
      }
    }
  });
