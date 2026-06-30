import { z } from "zod";

import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2BedrockCredentials,
  type LighthouseV2Configuration,
  type LighthouseV2ConfigurationInput,
  type LighthouseV2Credentials,
  type LighthouseV2OpenAICompatibleCredentials,
  type LighthouseV2OpenAICredentials,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

export const BUSINESS_CONTEXT_LIMIT = 5000;

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
};

export function getFormDefaults(
  configuration?: LighthouseV2Configuration,
): LighthouseV2ConfigFormValues {
  return {
    ...EMPTY_FORM_VALUES,
    baseUrl: configuration?.baseUrl ?? "",
  };
}

export function buildLighthouseV2ConfigFormSchema(
  provider: LighthouseV2ProviderType,
  hasConfiguration: boolean,
) {
  return lighthouseV2ConfigFormSchemaBase.superRefine((data, ctx) => {
    const apiKey = data.apiKey.trim();
    const baseUrl = data.baseUrl.trim();

    if (
      provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE &&
      !baseUrl
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base URL is required for OpenAI-compatible providers.",
        path: ["baseUrl"],
      });
    }

    // Presence is enforced above per provider; here we only reject malformed
    // values so strings like "foo" never reach the Cloud API.
    if (baseUrl && !isValidUrl(baseUrl)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base URL must be a valid URL.",
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

function isValidUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

// Builds the provider-keyed discriminated input from the runtime `provider` and
// the credentials the form assembled for it. This is the single place where the
// dynamic provider value is narrowed to a concrete variant, so the casts stay
// confined here while every typed caller of `LighthouseV2ConfigurationInput`
// gets full discriminated-union checking.
export function buildLighthouseV2ConfigurationInput(
  provider: LighthouseV2ProviderType,
  credentials: LighthouseV2Credentials,
  baseUrl: string | null,
): LighthouseV2ConfigurationInput {
  switch (provider) {
    case LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE:
      return {
        providerType: LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE,
        credentials: credentials as LighthouseV2OpenAICompatibleCredentials,
        baseUrl: baseUrl ?? "",
      };
    case LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK:
      return {
        providerType: LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK,
        credentials: credentials as LighthouseV2BedrockCredentials,
      };
    case LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI:
      return {
        providerType: LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI,
        credentials: credentials as LighthouseV2OpenAICredentials,
      };
  }
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
