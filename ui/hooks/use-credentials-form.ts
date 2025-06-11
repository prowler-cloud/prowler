import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";

import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { addCredentialsFormSchema, ProviderType } from "@/types";

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
  const formSchema = addCredentialsFormSchema(providerType);

  // Get default values based on provider type
  const getDefaultValues = (): CredentialsFormData => {
    const baseDefaults = {
      [ProviderCredentialFields.PROVIDER_ID]: providerId,
      [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
    };

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

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

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
  };
};
