"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  createLighthouseProvider,
  getLighthouseProviderByType,
  refreshProviderModels,
  testProviderConnection,
  updateLighthouseProviderByType,
} from "@/actions/lighthouse/lighthouse";
import { getTask } from "@/actions/task/tasks";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { checkTaskStatus } from "@/lib/helper";

interface ConnectLLMProviderProps {
  provider: string;
  mode?: string;
}

type AsyncResult<T = any> = {
  data?: T;
  errors?: Array<{ detail: string }>;
};

export const ConnectLLMProvider = ({
  provider,
  mode = "create",
}: ConnectLLMProviderProps) => {
  const router = useRouter();
  const [openAIForm, setOpenAIForm] = useState({
    apiKey: "",
    baseUrl: "",
  });
  const [bedrockForm, setBedrockForm] = useState({
    accessKeyId: "",
    secretAccessKey: "",
    region: "",
  });
  const [isAdditionalOpen, setIsAdditionalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [existingProviderId, setExistingProviderId] = useState<string | null>(
    null,
  );

  const providerName =
    provider === "bedrock"
      ? "Amazon Bedrock"
      : provider === "openai-compatible"
        ? "OpenAI Compatible"
        : "OpenAI";

  const isBedrock = provider === "bedrock";
  const isOpenAI = provider === "openai";
  const isOpenAICompatible = provider === "openai-compatible";
  const isEditMode = mode === "edit";

  // Fetch existing provider data if in edit mode
  useEffect(() => {
    const fetchProviderData = async () => {
      if (!isEditMode) return;

      setIsFetching(true);
      setError(null);

      try {
        // Lookup by provider type
        const result = await getLighthouseProviderByType(provider);

        if (result.errors) {
          throw new Error(
            result.errors[0]?.detail || "Failed to fetch provider",
          );
        }

        const providerData = result.data.attributes;
        // Only pre-populate base URL for providers that support it
        if ((isOpenAI || isOpenAICompatible) && providerData.base_url) {
          setOpenAIForm((prev) => ({
            ...prev,
            baseUrl: providerData.base_url,
          }));
          setIsAdditionalOpen(true);
        }

        // Store ID internally only
        setExistingProviderId(result.data.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsFetching(false);
      }
    };

    fetchProviderData();
  }, [isEditMode, provider, isOpenAI, isOpenAICompatible]);

  // Helper to handle API results and extract data or throw error
  const unwrapResult = <T,>(result: AsyncResult<T>, fallbackMsg: string): T => {
    if (result.errors) {
      throw new Error(result.errors[0]?.detail || fallbackMsg);
    }
    if (!result.data) {
      throw new Error(fallbackMsg);
    }
    return result.data;
  };

  const handleConnect = async () => {
    setIsLoading(true);
    setError(null);

    try {
      let providerId = existingProviderId;

      if (isEditMode) {
        // Update existing provider by type
        if (isBedrock) {
          const anyProvided =
            bedrockForm.accessKeyId ||
            bedrockForm.secretAccessKey ||
            bedrockForm.region;
          if (anyProvided) {
            if (
              !bedrockForm.accessKeyId.trim() ||
              !bedrockForm.secretAccessKey.trim() ||
              !bedrockForm.region.trim()
            ) {
              throw new Error(
                "All fields (Access Key ID, Secret Access Key, Region) are required.",
              );
            }
            const updateResult = await updateLighthouseProviderByType(
              provider,
              {
                credentials: {
                  access_key_id: bedrockForm.accessKeyId,
                  secret_access_key: bedrockForm.secretAccessKey,
                  region: bedrockForm.region,
                },
              },
            );
            unwrapResult(updateResult, "Failed to update provider");
          }
        } else {
          if (openAIForm.apiKey) {
            const updateResult = await updateLighthouseProviderByType(
              provider,
              {
                credentials: { api_key: openAIForm.apiKey },
                base_url: openAIForm.baseUrl || undefined,
              },
            );
            unwrapResult(updateResult, "Failed to update provider");
          } else if (openAIForm.baseUrl) {
            // Update only base URL if no API key provided
            const updateResult = await updateLighthouseProviderByType(
              provider,
              {
                base_url: openAIForm.baseUrl || undefined,
              },
            );
            unwrapResult(updateResult, "Failed to update provider");
          }
        }
        // providerId already set from useEffect
      } else {
        // Create new provider
        const createResult = await createLighthouseProvider(
          isBedrock
            ? {
                provider_type: provider,
                credentials: {
                  access_key_id: bedrockForm.accessKeyId,
                  secret_access_key: bedrockForm.secretAccessKey,
                  region: bedrockForm.region,
                },
              }
            : {
                provider_type: provider,
                credentials: { api_key: openAIForm.apiKey },
                base_url: openAIForm.baseUrl || undefined,
              },
        );
        const providerData = unwrapResult<{ id: string }>(
          createResult,
          "Failed to create provider",
        );
        providerId = providerData.id;
      }

      // Test connection (only if credentials were updated or it's a new provider)
      if (
        !isEditMode ||
        (isBedrock
          ? !!(
              bedrockForm.accessKeyId &&
              bedrockForm.secretAccessKey &&
              bedrockForm.region
            )
          : !!(openAIForm.apiKey || openAIForm.baseUrl))
      ) {
        const connectionResult = await testProviderConnection(providerId!);
        const connectionTaskData = unwrapResult<{ id: string }>(
          connectionResult,
          "Failed to start connection test",
        );

        const connectionStatus = await checkTaskStatus(connectionTaskData.id);
        if (!connectionStatus.completed) {
          throw new Error(connectionStatus.error || "Connection test failed");
        }

        const connectionTask = await getTask(connectionTaskData.id);
        const { connected, error: connectionError } =
          connectionTask.data.attributes.result;
        if (!connected) {
          throw new Error(connectionError || "Connection test failed");
        }

        // Refresh models (only if connection was tested)
        const modelsResult = await refreshProviderModels(providerId!);
        const modelsTaskData = unwrapResult<{ id: string }>(
          modelsResult,
          "Failed to start model refresh",
        );

        const modelsStatus = await checkTaskStatus(modelsTaskData.id);
        if (!modelsStatus.completed) {
          throw new Error(modelsStatus.error || "Model refresh failed");
        }

        const modelsTask = await getTask(modelsTaskData.id);
        if (modelsTask.data.attributes.result.error) {
          throw new Error(modelsTask.data.attributes.result.error);
        }
      }

      // Success - navigate to model selection
      router.push(
        `/lighthouse/config/select-model?provider=${provider}${isEditMode ? "&mode=edit" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const bedrockFieldsFilled =
    bedrockForm.accessKeyId.trim() !== "" &&
    bedrockForm.secretAccessKey.trim() !== "" &&
    bedrockForm.region.trim() !== "";

  const anyBedrockFieldProvided = !!(
    bedrockForm.accessKeyId ||
    bedrockForm.secretAccessKey ||
    bedrockForm.region
  );

  const isFormValid = isBedrock
    ? isEditMode
      ? anyBedrockFieldProvided
        ? bedrockFieldsFilled
        : true
      : bedrockFieldsFilled
    : isEditMode
      ? true
      : isOpenAICompatible
        ? openAIForm.apiKey.trim() !== "" && openAIForm.baseUrl.trim() !== ""
        : openAIForm.apiKey.trim() !== "";

  if (isFetching) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-sm text-gray-600 dark:text-gray-400">
          Loading provider configuration...
        </div>
      </div>
    );
  }

  return (
    <div className="flex w-full flex-col gap-6">
      <div>
        <h2 className="mb-2 text-xl font-semibold">
          {isEditMode ? `Update ${providerName}` : `Connect to ${providerName}`}
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          {isEditMode
            ? `Update your API credentials or settings for ${providerName}.`
            : `Enter your API credentials to connect to ${providerName}.`}
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      <div className="flex flex-col gap-4">
        {isBedrock ? (
          <>
            <div>
              <label
                htmlFor="accessKeyId"
                className="mb-2 block text-sm font-medium"
              >
                AWS Access Key ID{" "}
                {!isEditMode && <span className="text-red-500">*</span>}
              </label>
              <input
                id="accessKeyId"
                type="text"
                value={bedrockForm.accessKeyId}
                onChange={(e) =>
                  setBedrockForm((prev) => ({
                    ...prev,
                    accessKeyId: e.target.value,
                  }))
                }
                placeholder="Enter the AWS Access Key ID"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
              />
            </div>
            <div>
              <label
                htmlFor="secretAccessKey"
                className="mb-2 block text-sm font-medium"
              >
                AWS Secret Access Key{" "}
                {!isEditMode && <span className="text-red-500">*</span>}
              </label>
              <input
                id="secretAccessKey"
                type="password"
                value={bedrockForm.secretAccessKey}
                onChange={(e) =>
                  setBedrockForm((prev) => ({
                    ...prev,
                    secretAccessKey: e.target.value,
                  }))
                }
                placeholder="Enter the AWS Secret Access Key"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
              />
            </div>
            <div>
              <label
                htmlFor="region"
                className="mb-2 block text-sm font-medium"
              >
                AWS Region{" "}
                {!isEditMode && <span className="text-red-500">*</span>}
              </label>
              <input
                id="region"
                type="text"
                value={bedrockForm.region}
                onChange={(e) =>
                  setBedrockForm((prev) => ({
                    ...prev,
                    region: e.target.value,
                  }))
                }
                placeholder="Enter the AWS Region"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
              />
            </div>
          </>
        ) : (
          <>
            <div>
              <label
                htmlFor="apiKey"
                className="mb-2 block text-sm font-medium"
              >
                API Key {!isEditMode && <span className="text-red-500">*</span>}
                {isEditMode && (
                  <span className="text-xs text-gray-500">
                    (leave empty to keep existing)
                  </span>
                )}
              </label>
              <input
                id="apiKey"
                type="password"
                value={openAIForm.apiKey}
                onChange={(e) =>
                  setOpenAIForm((prev) => ({ ...prev, apiKey: e.target.value }))
                }
                placeholder={
                  isEditMode
                    ? "Enter new API key or leave empty"
                    : "Enter your API key"
                }
                className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
              />
            </div>

            {(isOpenAI || isOpenAICompatible) && (
              <Collapsible
                open={isAdditionalOpen}
                onOpenChange={setIsAdditionalOpen}
              >
                <CollapsibleTrigger className="flex items-center gap-2 text-sm font-medium text-gray-700 hover:text-gray-900 dark:text-gray-300 dark:hover:text-gray-100">
                  {isAdditionalOpen ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                  Additional Settings
                </CollapsibleTrigger>
                <CollapsibleContent className="mt-4">
                  <div>
                    <label
                      htmlFor="baseUrl"
                      className="mb-2 block text-sm font-medium"
                    >
                      Base URL
                    </label>
                    <input
                      id="baseUrl"
                      type="text"
                      value={openAIForm.baseUrl}
                      onChange={(e) =>
                        setOpenAIForm((prev) => ({
                          ...prev,
                          baseUrl: e.target.value,
                        }))
                      }
                      placeholder="https://api.openai.com/v1"
                      className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
                    />
                  </div>
                </CollapsibleContent>
              </Collapsible>
            )}
          </>
        )}

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
            {isLoading
              ? isEditMode
                ? "Updating..."
                : "Connecting..."
              : isEditMode
                ? "Continue"
                : "Connect"}
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
