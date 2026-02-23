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
  PROVIDER_UID: "providerUid",

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
  CERTIFICATE_CONTENT: "certificate_content",

  // GCP fields
  REFRESH_TOKEN: "refresh_token",
  SERVICE_ACCOUNT_KEY: "service_account_key",

  // Kubernetes fields
  KUBECONFIG_CONTENT: "kubeconfig_content",

  // GitHub fields
  PERSONAL_ACCESS_TOKEN: "personal_access_token",
  OAUTH_APP_TOKEN: "oauth_app_token",
  GITHUB_APP_ID: "github_app_id",
  GITHUB_APP_KEY: "github_app_key_content",

  // MongoDB Atlas fields
  ATLAS_PUBLIC_KEY: "atlas_public_key",
  ATLAS_PRIVATE_KEY: "atlas_private_key",

  // IaC fields
  REPOSITORY_URL: "repository_url",
  ACCESS_TOKEN: "access_token",

  // OCI fields
  OCI_USER: "user",
  OCI_FINGERPRINT: "fingerprint",
  OCI_KEY_FILE: "key_file",
  OCI_KEY_CONTENT: "key_content",
  OCI_TENANCY: "tenancy",
  OCI_REGION: "region",
  OCI_PASS_PHRASE: "pass_phrase",

  // Alibaba Cloud fields
  ALIBABACLOUD_ACCESS_KEY_ID: "access_key_id",
  ALIBABACLOUD_ACCESS_KEY_SECRET: "access_key_secret",
  ALIBABACLOUD_ROLE_ARN: "role_arn",
  ALIBABACLOUD_ROLE_SESSION_NAME: "role_session_name",

  // Cloudflare fields
  CLOUDFLARE_API_TOKEN: "api_token",
  CLOUDFLARE_API_KEY: "api_key",
  CLOUDFLARE_API_EMAIL: "api_email",

  // OpenStack fields
  OPENSTACK_CLOUDS_YAML_CONTENT: "clouds_yaml_content",
  OPENSTACK_CLOUDS_YAML_CLOUD: "clouds_yaml_cloud",
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
  PERSONAL_ACCESS_TOKEN: "/data/attributes/secret/personal_access_token",
  OAUTH_APP_TOKEN: "/data/attributes/secret/oauth_app_token",
  GITHUB_APP_ID: "/data/attributes/secret/github_app_id",
  GITHUB_APP_KEY: "/data/attributes/secret/github_app_key_content",
  REPOSITORY_URL: "/data/attributes/secret/repository_url",
  ACCESS_TOKEN: "/data/attributes/secret/access_token",
  CERTIFICATE_CONTENT: "/data/attributes/secret/certificate_content",
  OCI_USER: "/data/attributes/secret/user",
  OCI_FINGERPRINT: "/data/attributes/secret/fingerprint",
  OCI_KEY_FILE: "/data/attributes/secret/key_file",
  OCI_KEY_CONTENT: "/data/attributes/secret/key_content",
  OCI_TENANCY: "/data/attributes/secret/tenancy",
  OCI_REGION: "/data/attributes/secret/region",
  OCI_PASS_PHRASE: "/data/attributes/secret/pass_phrase",
  ATLAS_PUBLIC_KEY: "/data/attributes/secret/atlas_public_key",
  ATLAS_PRIVATE_KEY: "/data/attributes/secret/atlas_private_key",
  ALIBABACLOUD_ACCESS_KEY_ID: "/data/attributes/secret/access_key_id",
  ALIBABACLOUD_ACCESS_KEY_SECRET: "/data/attributes/secret/access_key_secret",
  ALIBABACLOUD_ROLE_ARN: "/data/attributes/secret/role_arn",
  ALIBABACLOUD_ROLE_SESSION_NAME: "/data/attributes/secret/role_session_name",
  CLOUDFLARE_API_TOKEN: "/data/attributes/secret/api_token",
  CLOUDFLARE_API_KEY: "/data/attributes/secret/api_key",
  CLOUDFLARE_API_EMAIL: "/data/attributes/secret/api_email",
  OPENSTACK_CLOUDS_YAML_CONTENT: "/data/attributes/secret/clouds_yaml_content",
  OPENSTACK_CLOUDS_YAML_CLOUD: "/data/attributes/secret/clouds_yaml_cloud",
} as const;

export type ErrorPointer = (typeof ErrorPointers)[keyof typeof ErrorPointers];
