"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  createLighthouseProvider,
  refreshProviderModels,
  testProviderConnection,
} from "@/actions/lighthouse/llm-providers";
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
}

type AsyncResult<T = any> = {
  data?: T;
  errors?: Array<{ detail: string }>;
};

export const ConnectLLMProvider = ({ provider }: ConnectLLMProviderProps) => {
  const router = useRouter();
  const [formData, setFormData] = useState({ apiKey: "", baseUrl: "" });
  const [isAdditionalOpen, setIsAdditionalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const providerName = "OpenAI";

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
      // Create provider
      const createResult = await createLighthouseProvider({
        provider_type: provider,
        credentials: { api_key: formData.apiKey },
        base_url: formData.baseUrl || undefined,
      });
      const providerData = unwrapResult<{ id: string }>(
        createResult,
        "Failed to create provider",
      );
      const providerId = providerData.id;

      // Test connection
      const connectionResult = await testProviderConnection(providerId);
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

      // Refresh models
      const modelsResult = await refreshProviderModels(providerId);
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

      // Success
      router.push(`/lighthouse/config/select-model?provider=${provider}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const isFormValid = formData.apiKey.trim() !== "";

  return (
    <div className="flex w-full flex-col gap-6">
      <div>
        <h2 className="mb-2 text-xl font-semibold">
          Connect to {providerName}
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Enter your API credentials to connect to {providerName}.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div>
          <label htmlFor="apiKey" className="mb-2 block text-sm font-medium">
            API Key <span className="text-red-500">*</span>
          </label>
          <input
            id="apiKey"
            type="password"
            value={formData.apiKey}
            onChange={(e) =>
              setFormData((prev) => ({ ...prev, apiKey: e.target.value }))
            }
            placeholder="Enter your API key"
            className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
          />
        </div>

        <Collapsible open={isAdditionalOpen} onOpenChange={setIsAdditionalOpen}>
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
                value={formData.baseUrl}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, baseUrl: e.target.value }))
                }
                placeholder="https://api.openai.com/v1"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 dark:border-gray-700 dark:bg-gray-800"
              />
            </div>
          </CollapsibleContent>
        </Collapsible>

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
            ariaLabel="Connect"
            variant="solid"
            color="action"
            size="md"
            isLoading={isLoading}
            isDisabled={!isFormValid}
            onPress={handleConnect}
          >
            {isLoading ? "Connecting..." : "Connect"}
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
