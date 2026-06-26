import { z } from "zod";

import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2Credentials,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

export const BUSINESS_CONTEXT_LIMIT = 1000;

export const CONNECTION_STATUS = {
  CONNECTED: "connected",
  FAILED: "failed",
  NOT_TESTED: "not-tested",
} as const;

export type ConnectionStatus =
  (typeof CONNECTION_STATUS)[keyof typeof CONNECTION_STATUS];

export const FEEDBACK_VARIANT = {
  ERROR: "error",
  SUCCESS: "success",
  INFO: "info",
} as const;

export type FeedbackVariant =
  (typeof FEEDBACK_VARIANT)[keyof typeof FEEDBACK_VARIANT];

export interface FeedbackState {
  title: string;
  description?: string;
  variant: FeedbackVariant;
}

const lighthouseV2ConfigFormSchemaBase = z.object({
  apiKey: z.string(),
  awsAccessKeyId: z.string(),
  awsSecretAccessKey: z.string(),
  awsRegionName: z.string(),
  baseUrl: z.string(),
  defaultModel: z.string(),
  businessContext: z.string().max(BUSINESS_CONTEXT_LIMIT, {
    error: "Business context cannot exceed 1000 characters.",
  }),
});

export type LighthouseV2ConfigFormValues = z.infer<
  typeof lighthouseV2ConfigFormSchemaBase
>;

export const EMPTY_FORM_VALUES: LighthouseV2ConfigFormValues = {
  apiKey: "",
  awsAccessKeyId: "",
  awsSecretAccessKey: "",
  awsRegionName: "",
  baseUrl: "",
  defaultModel: "",
  businessContext: "",
};

export function getFormDefaults(
  configuration?: LighthouseV2Configuration,
): LighthouseV2ConfigFormValues {
  return {
    ...EMPTY_FORM_VALUES,
    baseUrl: configuration?.baseUrl ?? "",
    defaultModel: configuration?.defaultModel ?? "",
    businessContext: configuration?.businessContext ?? "",
  };
}

export function buildLighthouseV2ConfigFormSchema(
  provider: LighthouseV2ProviderType,
  hasConfiguration: boolean,
) {
  return lighthouseV2ConfigFormSchemaBase.superRefine((data, ctx) => {
    const apiKey = data.apiKey.trim();

    if (
      provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE &&
      !data.baseUrl.trim()
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base URL is required for OpenAI-compatible providers.",
        path: ["baseUrl"],
      });
    }

    if (
      (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
        provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE) &&
      !hasConfiguration &&
      !apiKey
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "API key is required for new configurations.",
        path: ["apiKey"],
      });
    }

    if (provider !== LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) return;

    const hasAnyBedrockCredential =
      Boolean(data.awsAccessKeyId.trim()) ||
      Boolean(data.awsSecretAccessKey.trim()) ||
      Boolean(data.awsRegionName.trim());
    const shouldRequireBedrockCredentials =
      !hasConfiguration || hasAnyBedrockCredential;

    if (!shouldRequireBedrockCredentials) return;

    if (!data.awsAccessKeyId.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS access key ID is required.",
        path: ["awsAccessKeyId"],
      });
    }
    if (!data.awsSecretAccessKey.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS secret access key is required.",
        path: ["awsSecretAccessKey"],
      });
    }
    if (!data.awsRegionName.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS region is required.",
        path: ["awsRegionName"],
      });
    }
  });
}

export function buildCredentialPayload(
  provider: LighthouseV2ProviderType,
  values: LighthouseV2ConfigFormValues,
  hasConfiguration: boolean,
): LighthouseV2Credentials | undefined {
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) {
    const hasBedrockCredentials =
      Boolean(values.awsAccessKeyId.trim()) ||
      Boolean(values.awsSecretAccessKey.trim()) ||
      Boolean(values.awsRegionName.trim());

    if (hasConfiguration && !hasBedrockCredentials) return undefined;

    return {
      aws_access_key_id: values.awsAccessKeyId.trim(),
      aws_secret_access_key: values.awsSecretAccessKey.trim(),
      aws_region_name: values.awsRegionName.trim(),
    };
  }

  if (hasConfiguration && !values.apiKey.trim()) return undefined;

  return { api_key: values.apiKey.trim() };
}

export function trimToNullable(value: string) {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function getConnectionStatus(
  configuration?: LighthouseV2Configuration,
): ConnectionStatus {
  if (configuration?.connected === true) return CONNECTION_STATUS.CONNECTED;
  if (configuration?.connected === false) return CONNECTION_STATUS.FAILED;
  return CONNECTION_STATUS.NOT_TESTED;
}
