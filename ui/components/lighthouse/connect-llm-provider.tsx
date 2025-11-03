"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  createLighthouseProvider,
  getLighthouseProviderByType,
  updateLighthouseProviderByType,
} from "@/actions/lighthouse/lighthouse";
import { CustomButton } from "@/components/ui/custom";

import { getMainFields, getProviderConfig } from "./llm-provider-registry";
import {
  isProviderFormValid,
  shouldTestConnection,
  testAndRefreshModels,
} from "./llm-provider-utils";

interface ConnectLLMProviderProps {
  provider: string;
  mode?: string;
}

type AsyncResult<T = any> = {
  data?: T;
  errors?: Array<{ detail: string }>;
};

type FormData = Record<string, string>;

export const ConnectLLMProvider = ({
  provider,
  mode = "create",
}: ConnectLLMProviderProps) => {
  const router = useRouter();
  const providerConfig = getProviderConfig(provider);
  const isEditMode = mode === "edit";

  // State
  const [formData, setFormData] = useState<FormData>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [existingProviderId, setExistingProviderId] = useState<string | null>(
    null,
  );
  const [connectionPhase, setConnectionPhase] = useState<string>("");

  // Fetch existing provider data in edit mode
  useEffect(() => {
    if (!isEditMode || !providerConfig) return;

    const fetchProviderData = async () => {
      setIsFetching(true);
      setError(null);

      try {
        const result = await getLighthouseProviderByType(provider);

        if (result.errors) {
          throw new Error(
            result.errors[0]?.detail || "Failed to fetch provider",
          );
        }

        setExistingProviderId(result.data.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsFetching(false);
      }
    };

    fetchProviderData();
  }, [isEditMode, provider, providerConfig]);

  // Helper: Extract data from API result or throw error
  const unwrapResult = <T,>(result: AsyncResult<T>, fallbackMsg: string): T => {
    if (result.errors) {
      throw new Error(result.errors[0]?.detail || fallbackMsg);
    }
    if (!result.data) {
      throw new Error(fallbackMsg);
    }
    return result.data;
  };

  // Build API payload from form data
  const buildPayload = (): Record<string, any> => {
    if (!providerConfig) return {};

    const payload: Record<string, any> = {};

    // Separate credential and non-credential fields
    const credentialFields = providerConfig.fields.filter(
      (f) => f.requiresConnectionTest,
    );
    const nonCredentialFields = providerConfig.fields.filter(
      (f) => !f.requiresConnectionTest,
    );

    // Build credentials object if any credential field has a value
    const credentials: Record<string, string> = {};
    credentialFields.forEach((field) => {
      if (formData[field.name]) {
        credentials[field.name] = formData[field.name];
      }
    });

    if (Object.keys(credentials).length > 0) {
      payload.credentials = credentials;
    }

    // Add non-credential fields to root level
    nonCredentialFields.forEach((field) => {
      if (formData[field.name]) {
        payload[field.name] = formData[field.name];
      }
    });

    return payload;
  };

  // Create or update provider
  const saveProvider = async (): Promise<string> => {
    const payload = buildPayload();

    if (isEditMode) {
      // Update existing provider
      if (Object.keys(payload).length > 0) {
        await updateLighthouseProviderByType(provider, payload);
      }
      return existingProviderId!;
    } else {
      // Create new provider
      const createResult = await createLighthouseProvider({
        provider_type: provider,
        credentials: payload.credentials || {},
        ...(payload.base_url && { base_url: payload.base_url }),
      });
      const providerData = unwrapResult<{ id: string }>(
        createResult,
        "Failed to create provider",
      );
      return providerData.id;
    }
  };

  // Main handler for connect/update
  const handleConnect = async () => {
    if (!providerConfig) return;

    setIsLoading(true);
    setError(null);
    setConnectionPhase("Connecting");

    try {
      // Step 1: Create or update provider
      const providerId = await saveProvider();

      // Step 2: Test connection only if credentials were provided
      if (shouldTestConnection(provider, formData)) {
        setConnectionPhase("Verifying");
        await testAndRefreshModels(providerId);
        setConnectionPhase("Loading models");
      }

      // Step 3: Navigate to model selection
      router.push(
        `/lighthouse/config/select-model?provider=${provider}${isEditMode ? "&mode=edit" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
      setConnectionPhase("");
    }
  };

  const handleFieldChange = (fieldName: string, value: string) => {
    setFormData((prev) => ({ ...prev, [fieldName]: value }));
  };

  // Early returns for error/loading states
  if (!providerConfig) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-sm text-red-600 dark:text-red-400">
          Provider configuration not found: {provider}
        </div>
      </div>
    );
  }

  if (isFetching) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-sm text-gray-600 dark:text-gray-400">
          Loading provider configuration...
        </div>
      </div>
    );
  }

  // Computed values
  const mainFields = getMainFields(provider);
  const isFormValid = isProviderFormValid(provider, formData, isEditMode);

  // Button text configuration
  const buttonText = {
    connect: {
      idle: "Connect",
      connecting: "Connecting...",
      verifying: "Verifying...",
      loadingModels: "Loading models...",
    },
    edit: {
      idle: "Continue",
      updating: "Updating...",
    },
  };

  // Determine current button text
  const getButtonText = () => {
    if (!isLoading) {
      return isEditMode ? buttonText.edit.idle : buttonText.connect.idle;
    }

    if (isEditMode) {
      return buttonText.edit.updating;
    }

    // Connect mode - use connectionPhase if available
    switch (connectionPhase) {
      case "Verifying":
        return buttonText.connect.verifying;
      case "Loading models":
        return buttonText.connect.loadingModels;
      default:
        return buttonText.connect.connecting;
    }
  };

  return (
    <div className="flex w-full flex-col gap-6">
      {/* Header */}
      <div>
        <h2 className="mb-2 text-xl font-semibold">
          {isEditMode
            ? `Update ${providerConfig.name}`
            : `Connect to ${providerConfig.name}`}
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          {isEditMode
            ? `Update your API credentials or settings for ${providerConfig.name}.`
            : `Enter your API credentials to connect to ${providerConfig.name}.`}
        </p>
      </div>

      {/* Error message */}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      {/* Form */}
      <div className="flex flex-col gap-4">
        {/* Main fields */}
        {mainFields.map((field) => (
          <div key={field.name}>
            <label
              htmlFor={field.name}
              className="mb-2 block text-sm font-medium"
            >
              {field.label}{" "}
              {!isEditMode && field.required && (
                <span className="text-red-500">*</span>
              )}
              {isEditMode && (
                <span className="text-xs text-gray-500">
                  (leave empty to keep existing)
                </span>
              )}
            </label>
            <input
              id={field.name}
              type={field.type}
              value={formData[field.name] || ""}
              onChange={(e) => handleFieldChange(field.name, e.target.value)}
              placeholder={
                isEditMode
                  ? `Enter new ${field.label.toLowerCase()} or leave empty`
                  : field.placeholder
              }
              className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
            />
          </div>
        ))}

        {/* Actions */}
        <div className="mt-4 flex justify-end gap-4">
          <CustomButton
            ariaLabel="Cancel"
            variant="bordered"
            color="secondary"
            size="md"
            onPress={() => router.push("/lighthouse/config")}
          >
            Cancel
          </CustomButton>
          <CustomButton
            ariaLabel={isEditMode ? "Update" : "Connect"}
            variant="solid"
            color="action"
            size="md"
            isLoading={isLoading}
            isDisabled={!isFormValid}
            onPress={handleConnect}
          >
            {getButtonText()}
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
