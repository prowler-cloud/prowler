/**
 * Centralized credential field names to avoid hardcoded strings
 * and provide type safety across the application
 */

// Provider credential field names
export const ProviderCredentialFields = {
  CREDENTIALS_TYPE: "credentials_type",
  CREDENTIALS_TYPE_AWS: "aws-sdk-default",
  CREDENTIALS_TYPE_ACCESS_SECRET_KEY: "access-secret-key",
  // Base fields for all providers
  PROVIDER_ID: "providerId",
  PROVIDER_TYPE: "providerType",
  PROVIDER_ALIAS: "providerAlias",

  // AWS fields
  AWS_ACCESS_KEY_ID: "aws_access_key_id",
  AWS_SECRET_ACCESS_KEY: "aws_secret_access_key",
  AWS_SESSION_TOKEN: "aws_session_token",
  ROLE_ARN: "role_arn",
  EXTERNAL_ID: "external_id",
  SESSION_DURATION: "session_duration",
  ROLE_SESSION_NAME: "role_session_name",

  // Azure/M365 fields
  CLIENT_ID: "client_id",
  CLIENT_SECRET: "client_secret",
  TENANT_ID: "tenant_id",
  USER: "user",
  PASSWORD: "password",

  // GCP fields
  REFRESH_TOKEN: "refresh_token",
  SERVICE_ACCOUNT_KEY: "service_account_key",

  // Kubernetes fields
  KUBECONFIG_CONTENT: "kubeconfig_content",
} as const;

// Type for credential field values
export type ProviderCredentialField =
  (typeof ProviderCredentialFields)[keyof typeof ProviderCredentialFields];

// API error pointer paths
export const ErrorPointers = {
  // Secret fields
  AWS_ACCESS_KEY_ID: "/data/attributes/secret/aws_access_key_id",
  AWS_SECRET_ACCESS_KEY: "/data/attributes/secret/aws_secret_access_key",
  AWS_SESSION_TOKEN: "/data/attributes/secret/aws_session_token",
  CLIENT_ID: "/data/attributes/secret/client_id",
  CLIENT_SECRET: "/data/attributes/secret/client_secret",
  USER: "/data/attributes/secret/user",
  PASSWORD: "/data/attributes/secret/password",
  TENANT_ID: "/data/attributes/secret/tenant_id",
  KUBECONFIG_CONTENT: "/data/attributes/secret/kubeconfig_content",
  REFRESH_TOKEN: "/data/attributes/secret/refresh_token",
  ROLE_ARN: "/data/attributes/secret/role_arn",
  EXTERNAL_ID: "/data/attributes/secret/external_id",
  SESSION_DURATION: "/data/attributes/secret/session_duration",
  ROLE_SESSION_NAME: "/data/attributes/secret/role_session_name",
  SERVICE_ACCOUNT_KEY: "/data/attributes/secret/service_account_key",
} as const;

export type ErrorPointer = (typeof ErrorPointers)[keyof typeof ErrorPointers];
