import {
  ErrorPointers,
  ProviderCredentialFields,
} from "./provider-credentials/provider-credential-fields";

/**
 * Error pointer to field name mappings for different types of forms
 * These can be imported and used with the useFormServerErrors hook
 */

// Mapping for provider credentials forms
export const PROVIDER_CREDENTIALS_ERROR_MAPPING: Record<string, string> = {
  [ErrorPointers.AWS_ACCESS_KEY_ID]: ProviderCredentialFields.AWS_ACCESS_KEY_ID,
  [ErrorPointers.AWS_SECRET_ACCESS_KEY]:
    ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
  [ErrorPointers.AWS_SESSION_TOKEN]: ProviderCredentialFields.AWS_SESSION_TOKEN,
  [ErrorPointers.CLIENT_ID]: ProviderCredentialFields.CLIENT_ID,
  [ErrorPointers.CLIENT_SECRET]: ProviderCredentialFields.CLIENT_SECRET,
  [ErrorPointers.USER]: ProviderCredentialFields.USER,
  [ErrorPointers.PASSWORD]: ProviderCredentialFields.PASSWORD,
  [ErrorPointers.TENANT_ID]: ProviderCredentialFields.TENANT_ID,
  [ErrorPointers.KUBECONFIG_CONTENT]:
    ProviderCredentialFields.KUBECONFIG_CONTENT,
  [ErrorPointers.REFRESH_TOKEN]: ProviderCredentialFields.REFRESH_TOKEN,
  [ErrorPointers.ROLE_ARN]: ProviderCredentialFields.ROLE_ARN,
  [ErrorPointers.EXTERNAL_ID]: ProviderCredentialFields.EXTERNAL_ID,
  [ErrorPointers.SESSION_DURATION]: ProviderCredentialFields.SESSION_DURATION,
  [ErrorPointers.ROLE_SESSION_NAME]: ProviderCredentialFields.ROLE_SESSION_NAME,
  [ErrorPointers.SERVICE_ACCOUNT_KEY]:
    ProviderCredentialFields.SERVICE_ACCOUNT_KEY,
  [ErrorPointers.ATLAS_PUBLIC_KEY]: ProviderCredentialFields.ATLAS_PUBLIC_KEY,
  [ErrorPointers.ATLAS_PRIVATE_KEY]: ProviderCredentialFields.ATLAS_PRIVATE_KEY,
  [ErrorPointers.CLOUDFLARE_API_TOKEN]:
    ProviderCredentialFields.CLOUDFLARE_API_TOKEN,
  [ErrorPointers.CLOUDFLARE_API_KEY]:
    ProviderCredentialFields.CLOUDFLARE_API_KEY,
  [ErrorPointers.CLOUDFLARE_API_EMAIL]:
    ProviderCredentialFields.CLOUDFLARE_API_EMAIL,
  [ErrorPointers.OPENSTACK_CLOUDS_YAML_CONTENT]:
    ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CONTENT,
  [ErrorPointers.OPENSTACK_CLOUDS_YAML_CLOUD]:
    ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CLOUD,
};
