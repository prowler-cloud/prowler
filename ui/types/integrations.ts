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
      path?: string;
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
  path: string;
  credentials: {
    aws_access_key_id?: string;
    aws_secret_access_key?: string;
    aws_session_token?: string;
    role_arn?: string;
    external_id?: string;
    role_session_name?: string;
    session_duration?: number;
  };
}

export const s3IntegrationFormSchema = z
  .object({
    integration_type: z.literal("amazon_s3"),
    bucket_name: z.string().min(1, "Bucket name is required"),
    path: z.string().optional(),
    credentials_type: z.enum(["static", "role"]),
    aws_access_key_id: z.string().optional(),
    aws_secret_access_key: z.string().optional(),
    aws_session_token: z.string().optional(),
    role_arn: z.string().optional(),
    external_id: z.string().optional(),
    role_session_name: z.string().optional(),
    session_duration: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.credentials_type === "static") {
      if (!data.aws_access_key_id) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "AWS Access Key ID is required for static credentials",
          path: ["aws_access_key_id"],
        });
      }
      if (!data.aws_secret_access_key) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "AWS Secret Access Key is required for static credentials",
          path: ["aws_secret_access_key"],
        });
      }
    } else if (data.credentials_type === "role") {
      if (!data.role_arn) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Role ARN is required for role-based credentials",
          path: ["role_arn"],
        });
      }
    }
  });

export const editIntegrationFormSchema = z.object({
  id: z.string(),
  integration_type: z.enum(["amazon_s3", "aws_security_hub", "jira", "slack"]),
  bucket_name: z.string().min(1, "Bucket name is required").optional(),
  path: z.string().optional(),
  credentials_type: z.enum(["static", "role"]).optional(),
  aws_access_key_id: z.string().optional(),
  aws_secret_access_key: z.string().optional(),
  aws_session_token: z.string().optional(),
  role_arn: z.string().optional(),
  external_id: z.string().optional(),
  role_session_name: z.string().optional(),
  session_duration: z.string().optional(),
});
