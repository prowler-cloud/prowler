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
