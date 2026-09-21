import { z } from "zod";

import { AWS_QUICK_ACCESS_METHOD } from "./types";

const AWS_ROLE_ARN_PATTERN =
  /^arn:aws(?:-[a-z]+)*:iam::(\d{12}):role\/[\w+=,.@/-]+$/;

const AWS_ROLE_ARN_MESSAGE =
  "Must be a valid IAM Role ARN (e.g. arn:aws:iam::123456789012:role/ProwlerScan)";

/** The 12-digit account id embedded in an IAM role ARN, or null when malformed. */
export const parseAwsAccountIdFromRoleArn = (roleArn: string) =>
  AWS_ROLE_ARN_PATTERN.exec(roleArn.trim())?.[1] ?? null;

export const awsQuickRoleSchema = z.object({
  roleArn: z
    .string()
    .trim()
    .min(1, "IAM Role ARN is required")
    .regex(AWS_ROLE_ARN_PATTERN, AWS_ROLE_ARN_MESSAGE),
});

export type AwsQuickRoleValues = z.infer<typeof awsQuickRoleSchema>;

export const awsQuickStaticSchema = z.object({
  accountId: z
    .string()
    .trim()
    .regex(/^\d{12}$/, "AWS Account ID must be exactly 12 digits"),
  awsAccessKeyId: z.string().trim().min(1, "AWS Access Key ID is required"),
  awsSecretAccessKey: z
    .string()
    .trim()
    .min(1, "AWS Secret Access Key is required"),
  awsSessionToken: z.string().trim().optional(),
});

export type AwsQuickStaticValues = z.infer<typeof awsQuickStaticSchema>;

export const awsQuickNameSchema = z.object({
  alias: z.string().trim().max(100, "Keep the name under 100 characters"),
});

export type AwsQuickNameValues = z.infer<typeof awsQuickNameSchema>;

export type AwsQuickConnectValues =
  | { method: typeof AWS_QUICK_ACCESS_METHOD.ROLE; values: AwsQuickRoleValues }
  | {
      method: typeof AWS_QUICK_ACCESS_METHOD.STATIC;
      values: AwsQuickStaticValues;
    };

/** Account id the provider will be registered under for the chosen method. */
export const resolveAwsQuickAccountId = (input: AwsQuickConnectValues) =>
  input.method === AWS_QUICK_ACCESS_METHOD.ROLE
    ? parseAwsAccountIdFromRoleArn(input.values.roleArn)
    : input.values.accountId.trim();
