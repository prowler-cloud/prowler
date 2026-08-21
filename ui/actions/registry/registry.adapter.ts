import { z } from "zod";

import {
  REGISTRY_ENDPOINT,
  REGISTRY_FAILURE,
  REGISTRY_SUBMISSION,
  type RegistryCredentialStatus,
  type RegistryCredentialSubmissionResult,
  type RegistryEndpoint,
  type RegistryFailureResult,
} from "@/types/registry";

const REGISTRY_TASK_PATH_PREFIX = "/api/v1/tasks/";
const REGISTRY_ERROR_CODE = {
  KEY_REJECTED: "registry_key_rejected",
  UNAVAILABLE: "registry_unavailable",
} as const;
const registryDiscoveryEndpoints = new Set<RegistryEndpoint>([
  REGISTRY_ENDPOINT.PROVIDERS,
  REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
]);

const credentialStatusSchema = z.object({
  data: z.object({
    attributes: z.object({
      configured: z.boolean(),
      is_valid: z.boolean(),
      scopes: z.array(z.string()),
      last_validated_at: z.string().optional(),
      validation_status: z.string().optional(),
      validation_pending: z.boolean(),
    }),
  }),
});

const taskSubmissionSchema = z.object({
  data: z.object({
    type: z.literal("tasks"),
    id: z.string().min(1),
  }),
});

const errorDocumentSchema = z.object({
  errors: z.array(z.object({ code: z.string().min(1) })).min(1),
});

export function adaptRegistryCredentialStatus(
  payload: unknown,
): RegistryCredentialStatus | null {
  const parsed = credentialStatusSchema.safeParse(payload);
  if (!parsed.success) return null;

  const { attributes } = parsed.data.data;
  return {
    configured: attributes.configured,
    isValid: attributes.is_valid,
    scopes: attributes.scopes,
    lastValidatedAt: attributes.last_validated_at,
    validationStatus: attributes.validation_status,
    validationPending: attributes.validation_pending,
  };
}

export async function parseRegistryCredentialSubmission(
  response: Response,
): Promise<RegistryCredentialSubmissionResult> {
  if (response.status !== 202) return { status: REGISTRY_SUBMISSION.ERROR };

  const parsed = taskSubmissionSchema.safeParse(
    await response.json().catch(() => undefined),
  );
  const taskId = parsed.success ? parsed.data.data.id : undefined;
  const location = response.headers.get("Content-Location");
  if (
    !taskId ||
    location !== `${REGISTRY_TASK_PATH_PREFIX}${encodeURIComponent(taskId)}`
  ) {
    return { status: REGISTRY_SUBMISSION.ERROR };
  }

  return { status: REGISTRY_SUBMISSION.PENDING, taskId };
}

export async function classifyRegistryFailure(
  response: Response,
  endpoint: RegistryEndpoint,
  credentialStatus: RegistryCredentialStatus | null,
): Promise<RegistryFailureResult> {
  if (response.status === 401 || response.status === 403) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }

  if (!isRegistryDiscoveryEndpoint(endpoint)) {
    return { status: REGISTRY_FAILURE.ERROR };
  }

  if (
    response.status === 409 &&
    credentialStatus !== null &&
    !hasActiveRegistryCredential(credentialStatus)
  ) {
    return { status: REGISTRY_FAILURE.ONBOARDING };
  }

  const code = await getRegistryErrorCode(response);
  if (response.status === 502 && code === REGISTRY_ERROR_CODE.KEY_REJECTED) {
    return { status: REGISTRY_FAILURE.RECONNECT };
  }
  if (response.status === 503 && code === REGISTRY_ERROR_CODE.UNAVAILABLE) {
    return { status: REGISTRY_FAILURE.UNAVAILABLE };
  }

  return { status: REGISTRY_FAILURE.ERROR };
}

function isRegistryDiscoveryEndpoint(endpoint: RegistryEndpoint) {
  return registryDiscoveryEndpoints.has(endpoint);
}

function hasActiveRegistryCredential(
  credentialStatus: RegistryCredentialStatus | null,
) {
  return Boolean(
    credentialStatus?.configured &&
      credentialStatus.isValid &&
      !credentialStatus.validationPending,
  );
}

async function getRegistryErrorCode(response: Response) {
  const parsed = errorDocumentSchema.safeParse(
    await response
      .clone()
      .json()
      .catch(() => undefined),
  );
  return parsed.success ? parsed.data.errors[0]?.code : undefined;
}
