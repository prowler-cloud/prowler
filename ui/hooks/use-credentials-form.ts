import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";

import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
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
      providerId,
      providerType,
    };

    switch (providerType) {
      case "aws":
        return {
          ...baseDefaults,
          aws_access_key_id: "",
          aws_secret_access_key: "",
          aws_session_token: "",
        };
      case "azure":
        return {
          ...baseDefaults,
          client_id: "",
          client_secret: "",
          tenant_id: "",
        };
      case "m365":
        return {
          ...baseDefaults,
          client_id: "",
          client_secret: "",
          tenant_id: "",
          user: "",
          password: "",
        };
      case "gcp":
        return {
          ...baseDefaults,
          client_id: "",
          client_secret: "",
          refresh_token: "",
        };
      case "kubernetes":
        return {
          ...baseDefaults,
          kubeconfig_content: "",
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
