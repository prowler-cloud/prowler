export const PROVIDER_SCHEMA_STATUS = {
  SUCCESS: "success",
  NOT_FOUND: "not_found",
  UNAVAILABLE: "unavailable",
  ACCESS_DENIED: "access_denied",
  ERROR: "error",
  MALFORMED: "malformed",
} as const;

export interface ProviderSchemaObject {
  readonly [keyword: string]: unknown;
}

export interface ProviderSecretTypes {
  readonly [secretType: string]: ProviderSchemaObject;
}

export interface ProviderSchemasSuccessResult {
  status: typeof PROVIDER_SCHEMA_STATUS.SUCCESS;
  providerType: string;
  secretTypes: ProviderSecretTypes;
}

export interface ProviderSchemasFailureResult {
  status: Exclude<
    (typeof PROVIDER_SCHEMA_STATUS)[keyof typeof PROVIDER_SCHEMA_STATUS],
    typeof PROVIDER_SCHEMA_STATUS.SUCCESS
  >;
}

export type ProviderSchemasResult =
  | ProviderSchemasSuccessResult
  | ProviderSchemasFailureResult;
