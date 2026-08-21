export const REGISTRY_ENDPOINT = {
  PROVIDERS: "providers",
  AVAILABLE_ARTIFACTS: "available_artifacts",
  CREDENTIAL: "credential",
  MUTATION: "mutation",
} as const;

export type RegistryEndpoint =
  (typeof REGISTRY_ENDPOINT)[keyof typeof REGISTRY_ENDPOINT];

export const REGISTRY_FAILURE = {
  ACCESS_DENIED: "access_denied",
  ONBOARDING: "onboarding",
  RECONNECT: "reconnect",
  UNAVAILABLE: "unavailable",
  ERROR: "error",
} as const;

export type RegistryFailureResult =
  | { status: typeof REGISTRY_FAILURE.ACCESS_DENIED }
  | { status: typeof REGISTRY_FAILURE.ONBOARDING }
  | { status: typeof REGISTRY_FAILURE.RECONNECT }
  | { status: typeof REGISTRY_FAILURE.UNAVAILABLE }
  | { status: typeof REGISTRY_FAILURE.ERROR };

export const REGISTRY_SUBMISSION = {
  PENDING: "pending",
  ERROR: "error",
} as const;

export type RegistryCredentialSubmissionResult =
  | {
      status: typeof REGISTRY_SUBMISSION.PENDING;
      taskId: string;
    }
  | { status: typeof REGISTRY_SUBMISSION.ERROR };

export interface RegistryCredentialStatus {
  configured: boolean;
  isValid: boolean;
  scopes: string[];
  lastValidatedAt?: string;
  validationStatus?: string;
  validationPending: boolean;
}

export const REGISTRY_CATALOG = {
  COMPLETE: "complete",
  INCOMPLETE: "incomplete",
} as const;
export const REGISTRY_CATALOG_INCOMPLETE_REASON = {
  CONFLICTING_DUPLICATE: "conflicting_duplicate",
  COUNT_MISMATCH: "count_mismatch",
  GUARD_EXHAUSTED: "guard_exhausted",
  INVALID_PAGE: "invalid_page",
  INVALID_RESOURCE: "invalid_resource",
  PAGE_FAILED: "page_failed",
} as const;
export type RegistryCatalogIncompleteReason =
  (typeof REGISTRY_CATALOG_INCOMPLETE_REASON)[keyof typeof REGISTRY_CATALOG_INCOMPLETE_REASON];

export interface RegistryArtifactOwner {
  name: string;
  type: string;
}

export interface RegistryCatalogArtifact {
  normalizedName: string;
  name?: string;
  description?: string;
  latestVersion?: string;
  providers: string[];
  isVerified: boolean;
  isOfficial: boolean;
  isMeta: boolean;
  hasProvider: boolean;
  hasChecks: boolean;
  hasCompliance: boolean;
  versionCount: number;
  totalDownloads: number;
  owners: RegistryArtifactOwner[];
}

export interface RegistryTenantArtifact {
  normalizedName: string;
  versionSpec: string;
  insertedAt?: string;
  updatedAt?: string;
}

export type RegistryCatalogResult =
  | {
      status: typeof REGISTRY_CATALOG.COMPLETE;
      artifacts: RegistryCatalogArtifact[];
    }
  | {
      status: typeof REGISTRY_CATALOG.INCOMPLETE;
      reason: RegistryCatalogIncompleteReason;
      collectedCount: number;
    };
