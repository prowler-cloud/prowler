import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2ConfigurationInput,
  type LighthouseV2ConfigurationUpdateInput,
  type LighthouseV2Credentials,
  type LighthouseV2Message,
  type LighthouseV2Part,
  type LighthouseV2ProviderType,
  type LighthouseV2Session,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
  type LighthouseV2Task,
  type LighthouseV2TenantConfiguration,
  type LighthouseV2TenantConfigurationUpdateInput,
} from "@/app/(prowler)/lighthouse/_types";

export interface JsonApiResource<TAttributes> {
  id: string;
  type: string;
  attributes: TAttributes;
  meta?: Record<string, unknown>;
}

export interface JsonApiDocument<TData> {
  data?: TData;
  meta?: Record<string, unknown>;
  links?: Record<string, string | null>;
  error?: string;
  errors?: unknown[];
  status?: number;
}

interface ConfigurationAttributes {
  provider_type: LighthouseV2ProviderType;
  base_url: string | null;
  default_model?: string | null;
  connected: boolean | null;
  connection_last_checked_at: string | null;
  inserted_at: string;
  updated_at: string;
}

interface TenantConfigurationAttributes {
  business_context?: string | null;
  default_provider?: LighthouseV2ProviderType | "";
  default_models?: Record<string, string> | null;
}

interface SupportedProviderAttributes {
  name: string;
}

interface SupportedModelAttributes {
  max_input_tokens: number | null;
  max_output_tokens: number | null;
  supports_function_calling: boolean | null;
  supports_vision: boolean | null;
  supports_reasoning: boolean | null;
}

interface SessionAttributes {
  title: string | null;
  is_archived: boolean;
  inserted_at: string;
  updated_at: string;
  active_celery_task_id?: string | null;
}

interface MessageAttributes {
  role: "user" | "assistant";
  model: string | null;
  token_usage: unknown;
  inserted_at: string;
  parts?: UnknownPartResource[];
}

interface PartAttributes {
  id?: string;
  part_type: "text" | "reasoning" | "tool_call";
  content: unknown;
  tool_call_outcome?: string | null;
  inserted_at?: string | null;
  updated_at?: string | null;
}

type UnknownPartResource =
  | JsonApiResource<PartAttributes>
  | (PartAttributes & { id?: string });

interface TaskAttributes {
  inserted_at?: string;
  completed_at?: string | null;
  name?: string | null;
  state: string;
  metadata?: unknown;
  result?: unknown;
}

interface ValidationSuccess {
  success: true;
}

interface ValidationFailure {
  success: false;
  error: string;
}

type ValidationResult = ValidationSuccess | ValidationFailure;

export function getJsonApiArray<TResource>(
  document: JsonApiDocument<TResource[]>,
): TResource[] {
  return document.data ?? [];
}

export function mapLighthouseV2Configuration(
  resource: JsonApiResource<ConfigurationAttributes>,
): LighthouseV2Configuration {
  return {
    id: resource.id,
    providerType: resource.attributes.provider_type,
    baseUrl: resource.attributes.base_url,
    defaultModel: resource.attributes.default_model ?? null,
    connected: resource.attributes.connected,
    connectionLastCheckedAt: resource.attributes.connection_last_checked_at,
    insertedAt: resource.attributes.inserted_at,
    updatedAt: resource.attributes.updated_at,
  };
}

export function mapLighthouseV2TenantConfiguration(
  resource: JsonApiResource<TenantConfigurationAttributes>,
): LighthouseV2TenantConfiguration {
  return {
    id: resource.id,
    businessContext: resource.attributes.business_context ?? "",
    defaultProvider: resource.attributes.default_provider ?? "",
    defaultModels: resource.attributes.default_models ?? {},
  };
}

export function mapLighthouseV2Provider(
  resource: JsonApiResource<SupportedProviderAttributes>,
): LighthouseV2SupportedProvider {
  return {
    id: resource.id as LighthouseV2ProviderType,
    name: resource.attributes.name,
  };
}

export function mapLighthouseV2Model(
  resource: JsonApiResource<SupportedModelAttributes>,
): LighthouseV2SupportedModel {
  return {
    id: resource.id,
    maxInputTokens: resource.attributes.max_input_tokens,
    maxOutputTokens: resource.attributes.max_output_tokens,
    supportsFunctionCalling: resource.attributes.supports_function_calling,
    supportsVision: resource.attributes.supports_vision,
    supportsReasoning: resource.attributes.supports_reasoning,
  };
}

export function mapLighthouseV2Session(
  resource: JsonApiResource<SessionAttributes>,
): LighthouseV2Session {
  return {
    id: resource.id,
    title: resource.attributes.title,
    isArchived: resource.attributes.is_archived,
    insertedAt: resource.attributes.inserted_at,
    updatedAt: resource.attributes.updated_at,
    activeTaskId: resource.attributes.active_celery_task_id,
  };
}

export function mapLighthouseV2Message(
  resource: JsonApiResource<MessageAttributes>,
): LighthouseV2Message {
  return {
    id: resource.id,
    role: resource.attributes.role,
    model: resource.attributes.model,
    tokenUsage: resource.attributes.token_usage,
    insertedAt: resource.attributes.inserted_at,
    parts: (resource.attributes.parts ?? []).map(mapLighthouseV2Part),
  };
}

export function mapLighthouseV2Task(
  resource: JsonApiResource<TaskAttributes>,
): LighthouseV2Task {
  return {
    id: resource.id,
    name: resource.attributes.name ?? null,
    state: resource.attributes.state,
    insertedAt: resource.attributes.inserted_at,
    completedAt: resource.attributes.completed_at,
    metadata: resource.attributes.metadata,
    result: resource.attributes.result,
  };
}

export function buildLighthouseV2ConfigurationPayload(
  input: LighthouseV2ConfigurationInput,
) {
  return {
    data: {
      type: "lighthouse-ai-configurations",
      attributes: filterUndefinedAttributes({
        provider_type: input.providerType,
        credentials: input.credentials,
        base_url: input.baseUrl ?? null,
      }),
    },
  };
}

export function buildLighthouseV2ConfigurationUpdatePayload(
  configId: string,
  input: LighthouseV2ConfigurationUpdateInput,
) {
  return {
    data: {
      type: "lighthouse-ai-configurations",
      id: configId,
      attributes: filterUndefinedAttributes({
        credentials: input.credentials,
        base_url: input.baseUrl,
      }),
    },
  };
}

export function buildLighthouseV2TenantConfigurationUpdatePayload(
  input: LighthouseV2TenantConfigurationUpdateInput,
) {
  return {
    data: {
      type: "lighthouse-configurations",
      attributes: filterUndefinedAttributes({
        business_context: input.businessContext,
        default_provider: input.defaultProvider,
        default_models: input.defaultModels,
      }),
    },
  };
}

export function buildLighthouseV2SessionCreatePayload(title?: string | null) {
  return {
    data: {
      type: "lighthouse-sessions",
      attributes: { title: title || null },
    },
  };
}

export function buildLighthouseV2SessionUpdatePayload(
  sessionId: string,
  attributes: { title?: string | null; isArchived?: boolean },
) {
  return {
    data: {
      type: "lighthouse-sessions",
      id: sessionId,
      attributes: filterUndefinedAttributes({
        title: attributes.title,
        is_archived: attributes.isArchived,
      }),
    },
  };
}

export function buildLighthouseV2MessagePayload(input: {
  text: string;
  provider: LighthouseV2ProviderType;
  model?: string | null;
}) {
  return {
    data: {
      type: "lighthouse-messages",
      attributes: filterUndefinedAttributes({
        parts: [
          {
            part_type: "text",
            content: { text: input.text },
          },
        ],
        provider: input.provider,
        model: input.model || undefined,
      }),
    },
  };
}

export function buildLighthouseV2CancelRunPayload(taskId: string) {
  return {
    data: {
      type: "lighthouse-run-cancellations",
      attributes: { task_id: taskId },
    },
  };
}

export function validateLighthouseV2ConfigurationInput(input: {
  providerType: LighthouseV2ProviderType;
  credentials?: LighthouseV2Credentials;
  baseUrl?: string | null;
}): ValidationResult {
  if (!input.credentials) {
    return { success: false, error: "Credentials are required." };
  }

  if (
    input.providerType === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE &&
    !input.baseUrl
  ) {
    return {
      success: false,
      error: "Base URL is required for OpenAI-compatible providers.",
    };
  }

  if (
    input.providerType !== LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE &&
    input.baseUrl
  ) {
    return {
      success: false,
      error: "Base URL is only supported for OpenAI-compatible providers.",
    };
  }

  if (
    input.providerType === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK &&
    !hasBedrockRegion(input.credentials)
  ) {
    return {
      success: false,
      error: "AWS region is required for Bedrock providers.",
    };
  }

  return { success: true };
}

function mapLighthouseV2Part(resource: UnknownPartResource): LighthouseV2Part {
  const attributes = "attributes" in resource ? resource.attributes : resource;
  const id =
    "id" in resource && resource.id ? resource.id : (attributes.id ?? "");

  return {
    id,
    type: attributes.part_type,
    content: attributes.content,
    toolCallOutcome: attributes.tool_call_outcome ?? null,
    insertedAt: attributes.inserted_at ?? null,
    updatedAt: attributes.updated_at ?? null,
  };
}

function filterUndefinedAttributes<T extends Record<string, unknown>>(
  attributes: T,
) {
  return Object.fromEntries(
    Object.entries(attributes).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}

function hasBedrockRegion(credentials: LighthouseV2Credentials): boolean {
  return (
    "aws_region_name" in credentials && Boolean(credentials.aws_region_name)
  );
}
