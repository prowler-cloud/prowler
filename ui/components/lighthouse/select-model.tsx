"use client";

import { Icon } from "@iconify/react";
import { useEffect, useState } from "react";

import {
  getLighthouseModelIds,
  getTenantConfig,
  updateTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { CustomButton } from "@/components/ui/custom";

interface SelectModelProps {
  provider: string;
  mode?: string;
  onSelect: () => void;
}

interface Model {
  id: string;
  name: string;
}

export const SelectModel = ({
  provider,
  mode = "create",
  onSelect,
}: SelectModelProps) => {
  const [selectedModel, setSelectedModel] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [models, setModels] = useState<Model[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const isEditMode = mode === "edit";

  const fetchModels = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await getLighthouseModelIds(provider);

      if (result.errors) {
        throw new Error(result.errors[0]?.detail || "Failed to fetch models");
      }

      const models = result.data || [];
      setModels(models);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setModels([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchModels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSelect = async () => {
    if (!selectedModel) return;

    setIsSaving(true);
    setError(null);

    try {
      const currentConfig = await getTenantConfig();
      const existingDefaults =
        currentConfig?.data?.attributes?.default_models || {};
      const existingDefaultProvider =
        currentConfig?.data?.attributes?.default_provider || "";

      const mergedDefaults = {
        ...existingDefaults,
        [provider]: selectedModel,
      };

      // Prepare update payload
      const updatePayload: {
        default_models: Record<string, string>;
        default_provider?: string;
      } = {
        default_models: mergedDefaults,
      };

      // Set this provider as default if no default provider is currently set
      if (!existingDefaultProvider) {
        updatePayload.default_provider = provider;
      }

      const result = await updateTenantConfig(updatePayload);

      if (result.errors) {
        throw new Error(
          result.errors[0]?.detail || "Failed to save default model",
        );
      }

      onSelect();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSaving(false);
    }
  };

  // Filter models based on search query
  const filteredModels = models.filter(
    (model) =>
      model.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      model.id.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <div className="flex w-full flex-col gap-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="mb-2 text-xl font-semibold">
            {isEditMode ? "Update Default Model" : "Select Default Model"}
          </h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {isEditMode
              ? "Update the default model to use with this provider."
              : "Choose the default model to use with this provider."}
          </p>
        </div>
        <button
          onClick={fetchModels}
          disabled={isLoading}
          className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 disabled:opacity-50 dark:text-gray-300 dark:hover:bg-gray-800"
          aria-label="Refresh models"
        >
          <Icon
            icon="heroicons:arrow-path"
            className={`h-5 w-5 ${isLoading ? "animate-spin" : ""}`}
          />
          <span>{isLoading ? "Refreshing..." : "Refresh"}</span>
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      {!isLoading && models.length > 0 && (
        <div className="relative">
          <Icon
            icon="heroicons:magnifying-glass"
            className="pointer-events-none absolute top-1/2 left-3 h-5 w-5 -translate-y-1/2 text-gray-400"
          />
          <input
            type="text"
            placeholder="Search models..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-gray-300 py-2.5 pr-4 pl-11 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-white"
          />
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Icon
            icon="heroicons:arrow-path"
            className="h-8 w-8 animate-spin text-gray-400"
          />
        </div>
      ) : models.length === 0 ? (
        <div className="rounded-lg border border-gray-200 bg-gray-50 p-8 text-center dark:border-gray-700 dark:bg-gray-800">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            No models available. Click refresh to fetch models.
          </p>
        </div>
      ) : filteredModels.length === 0 ? (
        <div className="rounded-lg border border-gray-200 bg-gray-50 p-8 text-center dark:border-gray-700 dark:bg-gray-800">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            No models found matching &quot;{searchQuery}&quot;
          </p>
        </div>
      ) : (
        <div className="max-h-[calc(100vh-380px)] overflow-y-auto rounded-lg border border-gray-200 dark:border-gray-700">
          {filteredModels.map((model) => (
            <label
              key={model.id}
              htmlFor={`model-${provider}-${model.id}`}
              aria-label={model.name}
              className={`block cursor-pointer border-b border-gray-200 px-6 py-4 transition-colors last:border-b-0 dark:border-gray-700 ${
                selectedModel === model.id
                  ? "bg-blue-50 dark:bg-blue-900/20"
                  : "hover:bg-gray-50 dark:hover:bg-gray-800"
              }`}
            >
              <div className="flex items-center gap-4">
                <input
                  id={`model-${provider}-${model.id}`}
                  name="model"
                  type="radio"
                  checked={selectedModel === model.id}
                  onChange={() => setSelectedModel(model.id)}
                  className="h-4 w-4 cursor-pointer"
                />
                <span className="text-sm font-medium">{model.name}</span>
              </div>
            </label>
          ))}
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div className="flex justify-end">
          <CustomButton
            ariaLabel="Select Model"
            variant="solid"
            color="action"
            size="md"
            isDisabled={!selectedModel || isSaving}
            isLoading={isSaving}
            onPress={handleSelect}
          >
            {isSaving ? "Saving..." : "Select"}
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
