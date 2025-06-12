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
  ProviderType,
} from "@/types";

type CredentialsFormData = {
  providerId: string;
  providerType: ProviderType;
  [key: string]: any;
};

type UseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  onSubmit: (formData: FormData) => Promise<any>;
  successNavigationUrl: string;
};

export const useCredentialsForm = ({
  providerType,
  providerId,
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
    if (providerType === "gcp" && via === "service-account") {
      return addCredentialsServiceAccountFormSchema(providerType);
    }
    return addCredentialsFormSchema(providerType);
  };

  const formSchema = getFormSchema();

  // Get default values based on provider type and via parameter
  const getDefaultValues = (): CredentialsFormData => {
    const baseDefaults = {
      [ProviderCredentialFields.PROVIDER_ID]: providerId,
      [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
    };

    // AWS Role credentials
    if (providerType === "aws" && via === "role") {
      return {
        ...baseDefaults,
        [ProviderCredentialFields.CREDENTIALS_TYPE]: "aws-sdk-default",
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
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.CLIENT_SECRET]: "",
          [ProviderCredentialFields.TENANT_ID]: "",
          [ProviderCredentialFields.USER]: "",
          [ProviderCredentialFields.PASSWORD]: "",
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
      default:
        return baseDefaults;
    }
  };

  const form = useForm<CredentialsFormData>({
    resolver: zodResolver(formSchema),
    defaultValues: getDefaultValues(),
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
  const handleSubmit = async (values: CredentialsFormData) => {
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

  return {
    form,
    isLoading: form.formState.isSubmitting,
    handleSubmit,
    handleBackStep,
    searchParamsObj,
    externalId: session?.tenantId || "",
  };
};
