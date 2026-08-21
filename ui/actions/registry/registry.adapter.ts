import { z } from "zod";

import {
  REGISTRY_CATALOG,
  REGISTRY_CATALOG_INCOMPLETE_REASON,
  REGISTRY_ENDPOINT,
  REGISTRY_FAILURE,
  REGISTRY_SUBMISSION,
  type RegistryCatalogArtifact,
  type RegistryCatalogResult,
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

const REGISTRY_CATALOG_PAGE_SIZE = 100;
const REGISTRY_CATALOG_MAX_PAGES = 1000;
const safeInteger = z.number().int().nonnegative().safe();
// prettier-ignore
const catalogPageSchema = z.object({
  data: z.array(z.unknown()),
  meta: z.object({ pagination: z.object({ page: safeInteger, pages: safeInteger, count: safeInteger }) }),
});
// prettier-ignore
const catalogAttributesSchema = z.object({
  name: z.string().optional(), description: z.string().optional(), latest_version: z.string().optional(),
  providers: z.array(z.string().trim().min(1)).optional(),
  owners: z.array(z.object({ name: z.string().trim().min(1), type: z.string().trim().min(1) })).optional(),
  is_verified: z.boolean().optional(), is_official: z.boolean().optional(), is_meta: z.boolean().optional(),
  has_provider: z.boolean().optional(), has_checks: z.boolean().optional(), has_compliance: z.boolean().optional(),
  version_count: safeInteger.optional(), total_downloads: safeInteger.optional(),
});
const catalogResourceSchema = z.object({
  type: z.string().trim().min(1),
  id: z.string().trim().min(1),
  attributes: catalogAttributesSchema,
});
type RegistryCatalogPageFetcher = (
  page: number,
  searchParams: URLSearchParams,
) => Promise<unknown>;

export async function collectCompleteRegistryCatalog(
  fetchPage: RegistryCatalogPageFetcher,
): Promise<RegistryCatalogResult> {
  const resources: unknown[] = [];
  let expectedPages: number | undefined;
  let expectedCount: number | undefined;
  for (let page = 1; ; page += 1) {
    let payload: unknown;
    try {
      payload = await fetchPage(
        page,
        new URLSearchParams({
          "page[number]": String(page),
          "page[size]": String(REGISTRY_CATALOG_PAGE_SIZE),
        }),
      );
    } catch {
      return incomplete("PAGE_FAILED", resources.length);
    }
    const parsed = catalogPageSchema.safeParse(payload);
    if (!parsed.success) return incomplete("INVALID_PAGE", resources.length);
    const { count, page: responsePage, pages } = parsed.data.meta.pagination;
    if (
      responsePage !== page ||
      (expectedPages !== undefined &&
        (pages !== expectedPages || count !== expectedCount))
    )
      return incomplete("INVALID_PAGE", resources.length);
    expectedPages ??= pages;
    expectedCount ??= count;
    if (page === 1 && pages > 1 && count === 0 && parsed.data.data.length === 0)
      return incomplete("INVALID_PAGE", resources.length);
    if (pages === 0)
      return page === 1 && count === 0 && parsed.data.data.length === 0
        ? { status: REGISTRY_CATALOG.COMPLETE, artifacts: [] }
        : incomplete("INVALID_PAGE", resources.length);
    resources.push(...parsed.data.data);
    if (pages > REGISTRY_CATALOG_MAX_PAGES)
      return incomplete("GUARD_EXHAUSTED", resources.length);
    if (page === pages) break;
    if (page > pages) return incomplete("INVALID_PAGE", resources.length);
  }
  const merged = mergeCatalogResources(resources);
  return merged.status === REGISTRY_CATALOG.INCOMPLETE ||
    resources.length === expectedCount
    ? merged
    : incomplete("COUNT_MISMATCH", resources.length);
}

function mergeCatalogResources(resources: unknown[]): RegistryCatalogResult {
  const artifacts = new Map<string, RegistryCatalogArtifact>();
  for (const resource of resources) {
    const artifact = adaptCatalogArtifact(resource);
    if (!artifact) return incomplete("INVALID_RESOURCE", resources.length);
    const prior = artifacts.get(artifact.normalizedName);
    const next = prior ? mergeArtifacts(prior, artifact) : artifact;
    if (!next) return incomplete("CONFLICTING_DUPLICATE", resources.length);
    artifacts.set(next.normalizedName, next);
  }
  return {
    status: REGISTRY_CATALOG.COMPLETE,
    artifacts: Array.from(artifacts.values()).sort((left, right) =>
      compare(left.normalizedName, right.normalizedName),
    ),
  };
}

// prettier-ignore
function adaptCatalogArtifact(resource: unknown): RegistryCatalogArtifact | null {
  const parsed = catalogResourceSchema.safeParse(resource);
  if (!parsed.success) return null;
  const { attributes: a, id } = parsed.data;
  return {
    normalizedName: id, name: text(a.name), description: text(a.description), latestVersion: text(a.latest_version),
    providers: unique(a.providers?.map((provider) => provider.toLowerCase()) ?? []), owners: uniqueOwners(a.owners ?? []),
    isVerified: a.is_verified ?? false, isOfficial: a.is_official ?? false, isMeta: a.is_meta ?? false,
    hasProvider: a.has_provider ?? false, hasChecks: a.has_checks ?? false, hasCompliance: a.has_compliance ?? false,
    versionCount: a.version_count ?? 0, totalDownloads: a.total_downloads ?? 0,
  };
}

// prettier-ignore
function mergeArtifacts(left: RegistryCatalogArtifact, right: RegistryCatalogArtifact): RegistryCatalogArtifact | null {
  const [name, description, latestVersion] = [mergeText(left.name, right.name), mergeText(left.description, right.description), mergeText(left.latestVersion, right.latestVersion)];
  if ([name, description, latestVersion].some((value) => value === null)) return null;
  return {
    ...left, name: name ?? undefined, description: description ?? undefined, latestVersion: latestVersion ?? undefined,
    providers: unique([...left.providers, ...right.providers]), owners: uniqueOwners([...left.owners, ...right.owners]),
    isVerified: left.isVerified || right.isVerified, isOfficial: left.isOfficial || right.isOfficial, isMeta: left.isMeta || right.isMeta,
    hasProvider: left.hasProvider || right.hasProvider, hasChecks: left.hasChecks || right.hasChecks, hasCompliance: left.hasCompliance || right.hasCompliance,
    versionCount: Math.max(left.versionCount, right.versionCount), totalDownloads: Math.max(left.totalDownloads, right.totalDownloads),
  };
}

function incomplete(
  reason: keyof typeof REGISTRY_CATALOG_INCOMPLETE_REASON,
  collectedCount: number,
): RegistryCatalogResult {
  return {
    status: REGISTRY_CATALOG.INCOMPLETE,
    reason: REGISTRY_CATALOG_INCOMPLETE_REASON[reason],
    collectedCount,
  };
}
function text(value: string | undefined) {
  return value?.trim() || undefined;
}
function mergeText(left: string | undefined, right: string | undefined) {
  return left && right && left !== right ? null : (left ?? right);
}
function unique(values: string[]) {
  return Array.from(new Set(values)).sort(compare);
}
function uniqueOwners(owners: RegistryCatalogArtifact["owners"]) {
  return Array.from(
    new Map(
      owners.map((owner) => [`${owner.type}\u0000${owner.name}`, owner]),
    ).values(),
  ).sort((left, right) =>
    compare(
      `${left.type}\u0000${left.name}`,
      `${right.type}\u0000${right.name}`,
    ),
  );
}
function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}
