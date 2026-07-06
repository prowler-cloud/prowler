import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2ConfigurationInput,
  type LighthouseV2ConfigurationUpdateInput,
  type LighthouseV2Credentials,
  type LighthouseV2Message,
  type LighthouseV2MessageRole,
  type LighthouseV2Part,
  type LighthouseV2PartType,
  type LighthouseV2ProviderType,
  type LighthouseV2Session,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
  type LighthouseV2Task,
} from "@/app/(prowler)/lighthouse/_types";
import type { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";
import type {
  TaskAttributes as ApiTaskAttributes,
  TaskState,
} from "@/types/tasks";

interface ConfigurationAttributes {
  provider_type: string;
  base_url: string | null;
  default_model?: string | null;
  business_context?: string | null;
  connected: boolean | null;
  connection_last_checked_at: string | null;
  inserted_at: string;
  updated_at: string;
}

interface SupportedProviderAttributes {
  name: string;
}

interface SupportedModelAttributes {
  model_name?: string | null;
  name?: string | null;
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
}

interface MessageAttributes {
  role: LighthouseV2MessageRole;
  model: string | null;
  token_usage: unknown;
  inserted_at: string;
  parts?: UnknownPartResource[];
}

interface PartAttributes {
  id?: string;
  part_type: LighthouseV2PartType;
  content: unknown;
  tool_call_outcome?: string | null;
  inserted_at?: string | null;
  updated_at?: string | null;
}

type UnknownPartResource =
  | JsonApiResource<PartAttributes>
  | (PartAttributes & { id?: string });

// Extends the shared task attributes: the Lighthouse task resource always
// carries `state` plus scheduling metadata.
interface TaskAttributes extends ApiTaskAttributes {
  state: TaskState;
  inserted_at?: string;
  completed_at?: string | null;
  name?: string | null;
  metadata?: unknown;
}

interface ValidationSuccess {
  success: true;
}

interface ValidationFailure {
  success: false;
  error: string;
}

type ValidationResult = ValidationSuccess | ValidationFailure;

const LIGHTHOUSE_V2_API_PROVIDER_TYPE = {
  OPENAI: "openai",
  BEDROCK: "bedrock",
  OPENAI_COMPATIBLE: "openai_compatible",
} as const;

type LighthouseV2ApiProviderType =
  (typeof LIGHTHOUSE_V2_API_PROVIDER_TYPE)[keyof typeof LIGHTHOUSE_V2_API_PROVIDER_TYPE];

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
    providerType: normalizeLighthouseV2ProviderType(
      resource.attributes.provider_type,
    ),
    baseUrl: resource.attributes.base_url,
    defaultModel: resource.attributes.default_model ?? null,
    businessContext: resource.attributes.business_context ?? "",
    connected: resource.attributes.connected,
    connectionLastCheckedAt: resource.attributes.connection_last_checked_at,
    insertedAt: resource.attributes.inserted_at,
    updatedAt: resource.attributes.updated_at,
  };
}

export function mapLighthouseV2Provider(
  resource: JsonApiResource<SupportedProviderAttributes>,
): LighthouseV2SupportedProvider {
  return {
    id: normalizeLighthouseV2ProviderType(resource.id),
    name: resource.attributes.name,
  };
}

export function mapLighthouseV2Model(
  resource: JsonApiResource<SupportedModelAttributes>,
): LighthouseV2SupportedModel {
  return {
    id: resource.id,
    name:
      resource.attributes.model_name ?? resource.attributes.name ?? resource.id,
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
    parts: (resource.attributes.parts ?? []).map((part, index) =>
      mapLighthouseV2Part(part, index),
    ),
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
        provider_type: toLighthouseV2ApiProviderType(input.providerType),
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
        default_model: input.defaultModel,
        business_context: input.businessContext,
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
        provider: toLighthouseV2ApiProviderType(input.provider),
        model: input.model || undefined,
      }),
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

export function toLighthouseV2ApiProviderType(
  providerType: LighthouseV2ProviderType,
): LighthouseV2ApiProviderType {
  switch (providerType) {
    case LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI:
      return LIGHTHOUSE_V2_API_PROVIDER_TYPE.OPENAI;
    case LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK:
      return LIGHTHOUSE_V2_API_PROVIDER_TYPE.BEDROCK;
    case LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE:
      return LIGHTHOUSE_V2_API_PROVIDER_TYPE.OPENAI_COMPATIBLE;
  }
}

function mapLighthouseV2Part(
  resource: UnknownPartResource,
  index: number,
): LighthouseV2Part {
  const attributes = "attributes" in resource ? resource.attributes : resource;
  // Persisted parts carry an id; streamed/id-less parts fall back to a stable
  // per-message index so multiple id-less parts never collide on "" as a key.
  const id =
    ("id" in resource ? resource.id : attributes.id) ?? `part-${index}`;

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

function normalizeLighthouseV2ProviderType(
  providerType: string,
): LighthouseV2ProviderType {
  const normalized =
    providerType === "openai_compatible"
      ? LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE
      : providerType;

  // Validate at the adapter boundary so an unexpected backend id fails fast
  // here instead of crossing into the UI as a bogus "valid" provider.
  const allowed: readonly string[] = Object.values(LIGHTHOUSE_V2_PROVIDER_TYPE);
  if (!allowed.includes(normalized)) {
    throw new Error(`Unsupported Lighthouse v2 provider: ${providerType}`);
  }

  return normalized as LighthouseV2ProviderType;
}
