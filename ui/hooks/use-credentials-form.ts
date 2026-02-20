import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter, useSearchParams } from "next/navigation";
import { useSession } from "next-auth/react";
import { useForm } from "react-hook-form";

import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { filterEmptyValues } from "@/lib";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  addCredentialsFormSchema,
  addCredentialsRoleFormSchema,
  addCredentialsServiceAccountFormSchema,
  ApiResponse,
  ProviderType,
} from "@/types";

type UseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  providerUid?: string;
  onSubmit: (formData: FormData) => Promise<ApiResponse>;
  successNavigationUrl: string;
};

export const useCredentialsForm = ({
  providerType,
  providerId,
  providerUid,
  onSubmit,
  successNavigationUrl,
}: UseCredentialsFormProps) => {
  const router = useRouter();
  const searchParamsObj = useSearchParams();
  const { data: session } = useSession();
  const via = searchParamsObj.get("via");

  // Select the appropriate schema based on provider type and via parameter
  const getFormSchema = () => {
    if (providerType === "aws" && via === "role") {
      return addCredentialsRoleFormSchema(providerType);
    }
    if (providerType === "alibabacloud" && via === "role") {
      return addCredentialsRoleFormSchema(providerType);
    }
    if (providerType === "gcp" && via === "service-account") {
      return addCredentialsServiceAccountFormSchema(providerType);
    }
    // For GitHub, M365, and Cloudflare, we need to pass the via parameter to determine which fields are required
    if (
      providerType === "github" ||
      providerType === "m365" ||
      providerType === "cloudflare"
    ) {
      return addCredentialsFormSchema(providerType, via);
    }
    return addCredentialsFormSchema(providerType);
  };

  const formSchema = getFormSchema();

  // Get default values based on provider type and via parameter
  const getDefaultValues = () => {
    const baseDefaults = {
      [ProviderCredentialFields.PROVIDER_ID]: providerId,
      [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
    };

    // AWS Role credentials
    if (providerType === "aws" && via === "role") {
      const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
      const defaultCredentialsType = isCloudEnv
        ? "aws-sdk-default"
        : "access-secret-key";
      return {
        ...baseDefaults,
        [ProviderCredentialFields.CREDENTIALS_TYPE]: defaultCredentialsType,
        [ProviderCredentialFields.ROLE_ARN]: "",
        [ProviderCredentialFields.EXTERNAL_ID]: session?.tenantId || "",
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
        [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
        [ProviderCredentialFields.ROLE_SESSION_NAME]: "",
        [ProviderCredentialFields.SESSION_DURATION]: "3600",
      };
    }

    // GCP Service Account
    if (providerType === "gcp" && via === "service-account") {
      return {
        ...baseDefaults,
        [ProviderCredentialFields.SERVICE_ACCOUNT_KEY]: "",
      };
    }

    switch (providerType) {
      case "aws":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
          [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
          [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
        };
      case "azure":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.CLIENT_SECRET]: "",
          [ProviderCredentialFields.TENANT_ID]: "",
        };
      case "m365":
        // M365 credentials based on via parameter
        if (via === "app_client_secret") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.CLIENT_ID]: "",
            [ProviderCredentialFields.CLIENT_SECRET]: "",
            [ProviderCredentialFields.TENANT_ID]: "",
          };
        }
        if (via === "app_certificate") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.CLIENT_ID]: "",
            [ProviderCredentialFields.CERTIFICATE_CONTENT]: "",
            [ProviderCredentialFields.TENANT_ID]: "",
          };
        }
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.TENANT_ID]: "",
        };
      case "gcp":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.CLIENT_SECRET]: "",
          [ProviderCredentialFields.REFRESH_TOKEN]: "",
        };
      case "kubernetes":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.KUBECONFIG_CONTENT]: "",
        };
      case "github":
        // GitHub credentials based on via parameter
        if (via === "personal_access_token") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.PERSONAL_ACCESS_TOKEN]: "",
          };
        }
        if (via === "oauth_app") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.OAUTH_APP_TOKEN]: "",
          };
        }
        if (via === "github_app") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.GITHUB_APP_ID]: "",
            [ProviderCredentialFields.GITHUB_APP_KEY]: "",
          };
        }
        return baseDefaults;
      case "oraclecloud":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.OCI_USER]: "",
          [ProviderCredentialFields.OCI_FINGERPRINT]: "",
          [ProviderCredentialFields.OCI_KEY_CONTENT]: "",
          [ProviderCredentialFields.OCI_TENANCY]: providerUid || "",
          [ProviderCredentialFields.OCI_REGION]: "",
          [ProviderCredentialFields.OCI_PASS_PHRASE]: "",
        };
      case "mongodbatlas":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.ATLAS_PUBLIC_KEY]: "",
          [ProviderCredentialFields.ATLAS_PRIVATE_KEY]: "",
        };
      case "alibabacloud":
        if (via === "role") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.ALIBABACLOUD_ROLE_ARN]: "",
            [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]: "",
            [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]: "",
            [ProviderCredentialFields.ALIBABACLOUD_ROLE_SESSION_NAME]: "",
          };
        }
        return {
          ...baseDefaults,
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]: "",
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]: "",
        };
      case "cloudflare":
        // Cloudflare credentials based on via parameter
        if (via === "api_token") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.CLOUDFLARE_API_TOKEN]: "",
          };
        }
        if (via === "api_key") {
          return {
            ...baseDefaults,
            [ProviderCredentialFields.CLOUDFLARE_API_KEY]: "",
            [ProviderCredentialFields.CLOUDFLARE_API_EMAIL]: "",
          };
        }
        return baseDefaults;
      case "openstack":
        return {
          ...baseDefaults,
          [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CONTENT]: "",
          [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CLOUD]: "",
        };
      default:
        return baseDefaults;
    }
  };

  const defaultValues = getDefaultValues();

  const form = useForm({
    resolver: zodResolver(formSchema),
    defaultValues: defaultValues,
    mode: "onSubmit",
    reValidateMode: "onChange",
    criteriaMode: "all", // Show all errors for each field
  });

  const { handleServerResponse } = useFormServerErrors(
    form,
    PROVIDER_CREDENTIALS_ERROR_MAPPING,
  );

  // Handler for back button
  const handleBackStep = () => {
    const currentParams = new URLSearchParams(window.location.search);
    currentParams.delete("via");
    router.push(`?${currentParams.toString()}`);
  };

  // Form submit handler
  const handleSubmit = async (values: Record<string, unknown>) => {
    const formData = new FormData();

    // Filter out empty values first, then append all remaining values
    const filteredValues = filterEmptyValues(values);

    Object.entries(filteredValues).forEach(([key, value]) => {
      formData.append(key, value);
    });

    const data = await onSubmit(formData);

    const isSuccess = handleServerResponse(data);
    if (isSuccess) {
      router.push(successNavigationUrl);
    }
  };

  const { isSubmitting, errors } = form.formState;

  return {
    form,
    isLoading: isSubmitting,
    errors,
    handleSubmit,
    handleBackStep,
    searchParamsObj,
    externalId: session?.tenantId || "",
  };
};
