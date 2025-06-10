/**
 * Error pointer to field name mappings for different types of forms
 * These can be imported and used with the useFormServerErrors hook
 */

// Mapping for provider credentials forms
export const PROVIDER_CREDENTIALS_ERROR_MAPPING: Record<string, string> = {
  "/data/attributes/secret/aws_access_key_id": "aws_access_key_id",
  "/data/attributes/secret/aws_secret_access_key": "aws_secret_access_key",
  "/data/attributes/secret/aws_session_token": "aws_session_token",
  "/data/attributes/secret/client_id": "client_id",
  "/data/attributes/secret/client_secret": "client_secret",
  "/data/attributes/secret/user": "user",
  "/data/attributes/secret/password": "password",
  "/data/attributes/secret/tenant_id": "tenant_id",
  "/data/attributes/secret/kubeconfig_content": "kubeconfig_content",
  "/data/attributes/secret/refresh_token": "refresh_token",
  "/data/attributes/secret/role_arn": "role_arn",
  "/data/attributes/secret/external_id": "external_id",
  "/data/attributes/secret/session_duration": "session_duration",
  "/data/attributes/secret/role_session_name": "role_session_name",
  "/data/attributes/secret/service_account_key": "service_account_key",
  "/data/attributes/name": "secretName",
};
