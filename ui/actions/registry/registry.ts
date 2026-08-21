"use server";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { auth } from "@/auth.config";
import { apiBaseUrl } from "@/lib";
import { REGISTRY_ACCESS } from "@/lib/registry/access";
import { evaluateRegistryAccess } from "@/lib/registry/access.server";
import {
  REGISTRY_BOOTSTRAP_STATE,
  REGISTRY_CATALOG,
  REGISTRY_CREDENTIAL_ACTION,
  REGISTRY_CREDENTIAL_READ,
  REGISTRY_ENDPOINT,
  REGISTRY_FAILURE,
  type RegistryBootstrapResult,
  type RegistryBootstrapState,
  type RegistryCollectionsResult,
  type RegistryCredentialActionResult,
  type RegistryCredentialReadResult,
  type RegistryCredentialStatus,
  type RegistryFailureResult,
} from "@/types/registry";

import {
  adaptRegistryCredentialStatus,
  adaptRegistryTenantArtifacts,
  classifyRegistryFailure,
  collectCompleteRegistryCatalog,
  isRegistryCollection,
  parseRegistryCredentialSubmission,
  RegistryCatalogPageError,
} from "./registry.adapter";

type GuardedRegistryAccess = { accessToken: string; leaseDurationMs: number };

async function getRegistryAccess(): Promise<GuardedRegistryAccess | null> {
  const accessToken = (await auth())?.accessToken;
  const access = await evaluateRegistryAccess(accessToken);
  return access.status === REGISTRY_ACCESS.ELIGIBLE && accessToken?.trim()
    ? { accessToken, leaseDurationMs: access.leaseDurationMs }
    : null;
}

async function readRegistryResponse(
  accessToken: string,
  resource: string,
  endpoint: (typeof REGISTRY_ENDPOINT)[keyof typeof REGISTRY_ENDPOINT],
  credential: RegistryCredentialStatus | null = null,
  searchParams?: URLSearchParams,
): Promise<Response | RegistryFailureResult> {
  const url = new URL(`${apiBaseUrl}/registry/${resource}`);
  if (searchParams) url.search = searchParams.toString();

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      cache: "no-store",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${accessToken}`,
      },
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (response.ok) return response;

  return endpoint === REGISTRY_ENDPOINT.PROVIDERS ||
    endpoint === REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS
    ? classifyDiscoveryFailure(response, endpoint, accessToken, credential)
    : classifyRegistryFailure(response, endpoint, credential);
}

async function readRegistryCredential(accessToken: string) {
  const result = await readRegistryResponse(
    accessToken,
    "credential",
    REGISTRY_ENDPOINT.CREDENTIAL,
  );
  if (!(result instanceof Response)) return result;

  const credential = adaptRegistryCredentialStatus(
    await result.json().catch(() => undefined),
  );
  return credential
    ? { status: REGISTRY_CREDENTIAL_READ.STATUS, credential }
    : { status: REGISTRY_FAILURE.ERROR };
}

async function readRegistryTenantArtifacts(accessToken: string) {
  const result = await readRegistryResponse(
    accessToken,
    "my-artifacts",
    REGISTRY_ENDPOINT.MUTATION,
  );
  if (!(result instanceof Response)) return result;

  const tenantArtifacts = adaptRegistryTenantArtifacts(
    await result.json().catch(() => undefined),
  );
  return tenantArtifacts
    ? { status: "ready" as const, tenantArtifacts }
    : { status: REGISTRY_FAILURE.ERROR };
}

async function classifyDiscoveryFailure(
  response: Response,
  endpoint:
    | typeof REGISTRY_ENDPOINT.PROVIDERS
    | typeof REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
  accessToken: string,
  credential: RegistryCredentialStatus | null,
) {
  if (response.status === 409 && credential === null) {
    const currentCredential = await readRegistryCredential(accessToken);
    if (currentCredential.status === REGISTRY_FAILURE.ACCESS_DENIED) {
      return currentCredential;
    }
    credential =
      currentCredential.status === REGISTRY_CREDENTIAL_READ.STATUS
        ? currentCredential.credential
        : null;
  }
  return classifyRegistryFailure(response, endpoint, credential);
}

async function readRegistryProviders(
  accessToken: string,
  credential: RegistryCredentialStatus | null,
) {
  const result = await readRegistryResponse(
    accessToken,
    "providers",
    REGISTRY_ENDPOINT.PROVIDERS,
    credential,
  );
  if (!(result instanceof Response)) return result;
  return isRegistryCollection(await result.json().catch(() => undefined))
    ? { status: "ready" as const }
    : { status: REGISTRY_FAILURE.ERROR };
}

async function readCompleteRegistryCatalog(
  accessToken: string,
  credential: RegistryCredentialStatus | null,
) {
  try {
    return await collectCompleteRegistryCatalog(async (_page, searchParams) => {
      const result = await readRegistryResponse(
        accessToken,
        "available-artifacts",
        REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
        credential,
        searchParams,
      );
      if (!(result instanceof Response))
        throw new RegistryCatalogPageError(result);
      return result.json();
    });
  } catch (error) {
    return error instanceof RegistryCatalogPageError
      ? error.failure
      : { status: REGISTRY_FAILURE.ERROR };
  }
}

const hasActiveRegistryCredential = (credential: RegistryCredentialStatus) =>
  credential.configured && credential.isValid && !credential.validationPending;

async function credentialTaskCompleted(taskId: string) {
  const { ok, state } = await pollTaskUntilSettled(taskId, {
    maxAttempts: 20,
    delayMs: 3000,
  });
  return ok && state === "completed";
}

function credentialActionResult(
  priorCredential: RegistryCredentialStatus,
  credential: RegistryCredentialStatus,
  taskAccepted: boolean,
  taskCompleted: boolean,
): RegistryCredentialActionResult {
  if (taskCompleted && hasActiveRegistryCredential(credential)) {
    return { status: REGISTRY_CREDENTIAL_ACTION.CONNECTED, credential };
  }
  if (taskAccepted && credential.validationPending) {
    return { status: REGISTRY_CREDENTIAL_ACTION.PENDING, credential };
  }
  if (priorCredential.configured) {
    return {
      status: REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED,
      credential,
    };
  }
  return taskAccepted
    ? { status: REGISTRY_CREDENTIAL_ACTION.INVALID, credential }
    : { status: REGISTRY_FAILURE.ERROR };
}

function bootstrapReady(
  access: GuardedRegistryAccess,
  state: RegistryBootstrapState,
): RegistryBootstrapResult {
  return {
    status: REGISTRY_BOOTSTRAP_STATE.READY,
    leaseDurationMs: access.leaseDurationMs,
    state,
  };
}

function bootstrapFailure(
  access: GuardedRegistryAccess,
  failure: RegistryFailureResult,
): RegistryBootstrapResult {
  if (failure.status === REGISTRY_FAILURE.ACCESS_DENIED) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }
  return bootstrapReady(access, {
    status:
      failure.status === REGISTRY_FAILURE.ONBOARDING
        ? REGISTRY_BOOTSTRAP_STATE.ERROR
        : failure.status,
  });
}

export { refreshRegistryEligibility } from "@/lib/registry/access.server";

export async function getRegistryBootstrap(): Promise<RegistryBootstrapResult> {
  const access = await getRegistryAccess();
  if (!access) return { status: REGISTRY_FAILURE.ACCESS_DENIED };

  const credentialRead = await readRegistryCredential(access.accessToken);
  if (credentialRead.status !== REGISTRY_CREDENTIAL_READ.STATUS) {
    return bootstrapFailure(access, credentialRead);
  }
  const tenantArtifactsRead = await readRegistryTenantArtifacts(
    access.accessToken,
  );
  if (tenantArtifactsRead.status !== "ready") {
    return bootstrapFailure(access, tenantArtifactsRead);
  }

  const { credential } = credentialRead;
  const { tenantArtifacts } = tenantArtifactsRead;
  if (!hasActiveRegistryCredential(credential)) {
    return bootstrapReady(access, {
      status: credential.validationPending
        ? REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
        : REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
      credential,
      tenantArtifacts,
    });
  }

  const providers = await readRegistryProviders(access.accessToken, credential);
  if (providers.status !== "ready") return bootstrapFailure(access, providers);
  const catalog = await readCompleteRegistryCatalog(
    access.accessToken,
    credential,
  );
  if (catalog.status === REGISTRY_FAILURE.ACCESS_DENIED) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }
  if (catalog.status === REGISTRY_CATALOG.INCOMPLETE) {
    return bootstrapReady(access, {
      status: REGISTRY_BOOTSTRAP_STATE.INCOMPLETE,
      catalog,
    });
  }
  if (catalog.status !== REGISTRY_CATALOG.COMPLETE) {
    return bootstrapFailure(access, catalog);
  }

  return bootstrapReady(access, {
    status: REGISTRY_BOOTSTRAP_STATE.READY,
    credential,
    catalog,
    tenantArtifacts,
  });
}

export async function refreshRegistryCredential(): Promise<RegistryCredentialReadResult> {
  const access = await getRegistryAccess();
  if (!access) return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  return readRegistryCredential(access.accessToken);
}

export async function refreshRegistryCollections(): Promise<RegistryCollectionsResult> {
  const access = await getRegistryAccess();
  if (!access) return { status: REGISTRY_FAILURE.ACCESS_DENIED };

  const providers = await readRegistryProviders(access.accessToken, null);
  if (providers.status !== "ready") return providers;
  const catalog = await readCompleteRegistryCatalog(access.accessToken, null);
  if (catalog.status !== REGISTRY_CATALOG.COMPLETE) return catalog;
  const tenantArtifactsRead = await readRegistryTenantArtifacts(
    access.accessToken,
  );
  return tenantArtifactsRead.status === "ready"
    ? {
        status: REGISTRY_CATALOG.COMPLETE,
        catalog,
        tenantArtifacts: tenantArtifactsRead.tenantArtifacts,
      }
    : tenantArtifactsRead;
}

export async function submitRegistryCredential(
  key: string,
): Promise<RegistryCredentialActionResult> {
  const access = await getRegistryAccess();
  if (!access) return { status: REGISTRY_FAILURE.ACCESS_DENIED };

  const priorCredential = await readRegistryCredential(access.accessToken);
  if (priorCredential.status !== REGISTRY_CREDENTIAL_READ.STATUS) {
    return priorCredential;
  }

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/registry/credential`, {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
        Authorization: `Bearer ${access.accessToken}`,
      },
      body: JSON.stringify({
        data: { type: "registry-credentials", attributes: { api_key: key } },
      }),
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (response.status === 401 || response.status === 403) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }

  const submission = await parseRegistryCredentialSubmission(response);
  const taskCompleted =
    submission.status === "pending" &&
    (await credentialTaskCompleted(submission.taskId));
  const credential = await readRegistryCredential(access.accessToken);
  if (credential.status !== REGISTRY_CREDENTIAL_READ.STATUS) return credential;

  return credentialActionResult(
    priorCredential.credential,
    credential.credential,
    submission.status === "pending",
    taskCompleted,
  );
}

export async function disconnectRegistryCredential(): Promise<RegistryCredentialActionResult> {
  const access = await getRegistryAccess();
  if (!access) return { status: REGISTRY_FAILURE.ACCESS_DENIED };

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/registry/credential`, {
      method: "DELETE",
      cache: "no-store",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${access.accessToken}`,
      },
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (response.status === 401 || response.status === 403) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }

  const credential = await readRegistryCredential(access.accessToken);
  const tenantArtifacts = await readRegistryTenantArtifacts(access.accessToken);
  if (credential.status !== REGISTRY_CREDENTIAL_READ.STATUS) return credential;
  if (tenantArtifacts.status !== "ready") return tenantArtifacts;
  if (!response.ok) return { status: REGISTRY_FAILURE.ERROR };

  return {
    status: REGISTRY_CREDENTIAL_ACTION.DISCONNECTED,
    credential: credential.credential,
    tenantArtifacts: tenantArtifacts.tenantArtifacts,
  };
}
