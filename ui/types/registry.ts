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
  logoUrl?: string;
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

export const REGISTRY_CREDENTIAL_READ = {
  STATUS: "status",
} as const;

export type RegistryCredentialReadResult =
  | {
      status: typeof REGISTRY_CREDENTIAL_READ.STATUS;
      credential: RegistryCredentialStatus;
    }
  | RegistryFailureResult;

export const REGISTRY_CREDENTIAL_ACTION = {
  CONNECTED: "connected",
  DISCONNECTED: "disconnected",
  INVALID: "invalid",
  PENDING: "pending",
  REPLACEMENT_FAILED: "replacement_failed",
  SUBMITTED: "submitted",
} as const;

export type RegistryCredentialSubmitResult =
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.SUBMITTED;
      taskId: string;
      priorConfigured: boolean;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED;
      credential: RegistryCredentialStatus;
    }
  | RegistryFailureResult;

export type RegistryCredentialActionResult =
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.CONNECTED;
      credential: RegistryCredentialStatus;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.DISCONNECTED;
      credential: RegistryCredentialStatus;
      tenantArtifacts: RegistryTenantArtifact[];
    }
  | {
      status:
        | typeof REGISTRY_CREDENTIAL_ACTION.INVALID
        | typeof REGISTRY_CREDENTIAL_ACTION.PENDING
        | typeof REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED;
      credential: RegistryCredentialStatus;
    }
  | RegistryFailureResult;

type RegistryCompleteCatalog = Extract<
  RegistryCatalogResult,
  { status: typeof REGISTRY_CATALOG.COMPLETE }
>;
type RegistryIncompleteCatalog = Exclude<
  RegistryCatalogResult,
  RegistryCompleteCatalog
>;

export type RegistryCollectionsResult =
  | {
      status: typeof REGISTRY_CATALOG.COMPLETE;
      catalog: RegistryCompleteCatalog;
      tenantArtifacts: RegistryTenantArtifact[];
    }
  | RegistryIncompleteCatalog
  | RegistryFailureResult;

export const REGISTRY_MUTATION = {
  CONFIRMED: "confirmed",
  REFRESH_FAILED: "refresh_failed",
  REFUSED: "refused",
} as const;

export type RegistryMutationResult =
  | {
      status: typeof REGISTRY_MUTATION.CONFIRMED;
      tenantArtifacts: RegistryTenantArtifact[];
    }
  | {
      status: typeof REGISTRY_MUTATION.REFRESH_FAILED;
    }
  | {
      status: typeof REGISTRY_MUTATION.REFUSED;
      message: string;
    }
  | RegistryFailureResult;

export const REGISTRY_BOOTSTRAP_STATE = {
  ONBOARDING: "onboarding",
  VALIDATION_PENDING: "validation_pending",
  READY: "ready",
  RECONNECT: "reconnect",
  UNAVAILABLE: "unavailable",
  INCOMPLETE: "incomplete",
  ERROR: "error",
} as const;

export type RegistryBootstrapState =
  | {
      status:
        | typeof REGISTRY_BOOTSTRAP_STATE.ONBOARDING
        | typeof REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING;
      credential: RegistryCredentialStatus;
      tenantArtifacts: RegistryTenantArtifact[];
    }
  | {
      status: typeof REGISTRY_BOOTSTRAP_STATE.READY;
      credential: RegistryCredentialStatus;
      catalog: RegistryCompleteCatalog;
      tenantArtifacts: RegistryTenantArtifact[];
    }
  | {
      status:
        | typeof REGISTRY_BOOTSTRAP_STATE.RECONNECT
        | typeof REGISTRY_BOOTSTRAP_STATE.UNAVAILABLE
        | typeof REGISTRY_BOOTSTRAP_STATE.ERROR;
    }
  | {
      status: typeof REGISTRY_BOOTSTRAP_STATE.INCOMPLETE;
      catalog: RegistryIncompleteCatalog;
    };

export type RegistryBootstrapResult =
  | {
      status: typeof REGISTRY_BOOTSTRAP_STATE.READY;
      state: RegistryBootstrapState;
    }
  | { status: typeof REGISTRY_FAILURE.ACCESS_DENIED };
