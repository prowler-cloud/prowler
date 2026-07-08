import { z } from "zod";

/**
 * Valid AWS regions for Bedrock
 * Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/models-regions.html
 */
const AWS_BEDROCK_REGIONS = [
  // US Regions
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "us-gov-east-1",
  "us-gov-west-1",
  "ap-taipei-1",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-south-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ca-central-1",
  "eu-central-1",
  "eu-central-2",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "il-central-1",
  "me-central-1",
  "sa-east-1",
] as const;

/**
 * OpenAI API Key validation
 * Format: sk-... or sk-proj-... (32+ characters after prefix)
 */
export const openAIApiKeySchema = z
  .string()
  .min(1, "API key is required")
  .regex(
    /^sk-(proj-)?[A-Za-z0-9_-]{32,}$/,
    "Invalid API key format. OpenAI keys should start with 'sk-' or 'sk-proj-' followed by at least 32 characters",
  );

/**
 * AWS Access Key ID validation (long-term credentials only)
 * Format: AKIA... (20 characters total)
 */
export const awsAccessKeyIdSchema = z
  .string()
  .min(1, "AWS Access Key ID is required")
  .regex(/^AKIA[A-Z0-9]{16}$/, "Invalid AWS Access Key ID");

/**
 * AWS Secret Access Key validation
 * Format: 40 characters (alphanumeric + special chars)
 */
export const awsSecretAccessKeySchema = z
  .string()
  .min(1, "AWS Secret Access Key is required")
  .regex(/^[A-Za-z0-9/+=]{40}$/, "Invalid AWS Secret Access Key");

/**
 * AWS Region validation for Bedrock
 */
export const awsRegionSchema = z
  .string()
  .min(1, "AWS Region is required")
  .refine((region) => AWS_BEDROCK_REGIONS.includes(region as any), {
    message: `Invalid AWS region. Must be one of: ${AWS_BEDROCK_REGIONS.join(", ")}`,
  });

/**
 * Base URL validation for OpenAI-compatible providers
 * Must be a valid HTTP/HTTPS URL
 */
export const baseUrlSchema = z
  .string()
  .min(1, "Base URL is required")
  .refine((url) => {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  }, "Invalid URL format. Must be a valid HTTP or HTTPS URL");

/**
 * Generic API Key validation (for OpenAI-compatible providers with unknown formats)
 */
export const genericApiKeySchema = z
  .string()
  .min(8, "API key must be at least 8 characters")
  .max(512, "API key cannot exceed 512 characters");

/**
 * OpenAI Provider Credentials Schema
 */
export const openAICredentialsSchema = z.object({
  api_key: openAIApiKeySchema,
});

/**
 * Amazon Bedrock Provider Credentials Schema
 */
export const bedrockIamCredentialsSchema = z.object({
  access_key_id: awsAccessKeyIdSchema,
  secret_access_key: awsSecretAccessKeySchema,
  region: awsRegionSchema,
});

export const bedrockApiKeyCredentialsSchema = z.object({
  api_key: genericApiKeySchema,
  region: awsRegionSchema,
});

export const bedrockCredentialsSchema = z.union([
  bedrockIamCredentialsSchema,
  bedrockApiKeyCredentialsSchema,
]);

/**
 * OpenAI Compatible Provider Credentials Schema
 */
export const openAICompatibleCredentialsSchema = z.object({
  api_key: genericApiKeySchema,
});

/**
 * Full OpenAI Compatible Config (includes base_url)
 */
export const openAICompatibleConfigSchema = z.object({
  credentials: openAICompatibleCredentialsSchema,
  base_url: baseUrlSchema,
});

/**
 * Type exports for all provider credentials
 */
export type OpenAICredentials = z.infer<typeof openAICredentialsSchema>;
export type BedrockCredentials = z.infer<typeof bedrockCredentialsSchema>;
export type OpenAICompatibleCredentials = z.infer<
  typeof openAICompatibleCredentialsSchema
>;
