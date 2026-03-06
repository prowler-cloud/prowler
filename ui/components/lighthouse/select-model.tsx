"use client";

import { Icon } from "@iconify/react";
import { useEffect, useState } from "react";

import {
  getLighthouseModelIds,
  getTenantConfig,
  updateTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { Button } from "@/components/shadcn";
import type { LighthouseProvider } from "@/types/lighthouse";

import {
  getProviderIdByType,
  refreshModelsInBackground,
} from "./llm-provider-utils";

// Recommended models per provider
const RECOMMENDED_MODELS: Record<LighthouseProvider, Set<string>> = {
  openai: new Set(["gpt-5.2"]),
  bedrock: new Set([]),
  openai_compatible: new Set([]),
};

interface SelectModelProps {
  provider: LighthouseProvider;
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

  const isRecommended = (modelId: string) => {
    return RECOMMENDED_MODELS[provider]?.has(modelId) || false;
  };

  const fetchModels = async (triggerRefresh: boolean = false) => {
    setIsLoading(true);
    setError(null);

    try {
      // If triggerRefresh is true, trigger background job to refetch models from LLM provider API
      if (triggerRefresh) {
        const providerId = await getProviderIdByType(provider);
        await refreshModelsInBackground(providerId);
      }

      // Fetch models from database
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
        default_provider?: LighthouseProvider;
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

  // Filter models based on search query and sort with recommended models first
  const filteredModels = models
    .filter(
      (model) =>
        model.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        model.id.toLowerCase().includes(searchQuery.toLowerCase()),
    )
    .sort((a, b) => {
      const aRecommended = isRecommended(a.id);
      const bRecommended = isRecommended(b.id);
      // Recommended models first
      if (aRecommended && !bRecommended) return -1;
      if (!aRecommended && bRecommended) return 1;
      // Then alphabetically by name
      return a.name.localeCompare(b.name);
    });

  return (
    <div className="flex w-full flex-col gap-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="mb-2 text-xl font-semibold">
            {isEditMode ? "Update Default Model" : "Select Default Model"}
          </h2>
          <p className="text-text-neutral-secondary text-sm">
            {isEditMode
              ? "Update the default model to use with this provider."
              : "Choose the default model to use with this provider."}
          </p>
        </div>
        <button
          onClick={() => fetchModels(true)}
          disabled={isLoading}
          className="text-text-neutral-secondary hover:bg-bg-neutral-tertiary flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium disabled:opacity-50"
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
        <div className="border-border-error-primary bg-bg-fail-secondary rounded-lg border p-4">
          <p className="text-text-error text-sm">{error}</p>
        </div>
      )}

      {!isLoading && models.length > 0 && (
        <div className="relative">
          <Icon
            icon="heroicons:magnifying-glass"
            className="text-text-neutral-tertiary pointer-events-none absolute top-1/2 left-3 h-5 w-5 -translate-y-1/2"
          />
          <input
            type="text"
            placeholder="Search models..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="border-border-neutral-primary bg-bg-neutral-primary focus:border-button-primary focus:ring-button-primary w-full rounded-lg border py-2.5 pr-4 pl-11 text-sm focus:ring-1 focus:outline-none"
          />
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Icon
            icon="heroicons:arrow-path"
            className="text-text-neutral-tertiary h-8 w-8 animate-spin"
          />
        </div>
      ) : models.length === 0 ? (
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-lg border p-8 text-center">
          <p className="text-text-neutral-secondary text-sm">
            No models available. Click refresh to fetch models.
          </p>
        </div>
      ) : filteredModels.length === 0 ? (
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-lg border p-8 text-center">
          <p className="text-text-neutral-secondary text-sm">
            No models found matching &quot;{searchQuery}&quot;
          </p>
        </div>
      ) : (
        <div className="border-border-neutral-secondary minimal-scrollbar max-h-[calc(100vh-380px)] overflow-y-auto rounded-lg border">
          {filteredModels.map((model) => (
            <label
              key={model.id}
              htmlFor={`model-${provider}-${model.id}`}
              aria-label={model.name}
              className={`border-border-neutral-primary block cursor-pointer border-b px-6 py-4 transition-colors last:border-b-0 ${
                selectedModel === model.id
                  ? "bg-bg-neutral-secondary"
                  : "hover:bg-bg-neutral-tertiary"
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
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{model.name}</span>
                  {isRecommended(model.id) && (
                    <span className="bg-bg-pass-secondary text-text-success-primary inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium">
                      <Icon icon="heroicons:star-solid" className="h-3 w-3" />
                      Recommended
                    </span>
                  )}
                </div>
              </div>
            </label>
          ))}
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div className="flex justify-end">
          <Button
            aria-label="Select Model"
            disabled={!selectedModel || isSaving}
            onClick={handleSelect}
          >
            {isSaving ? "Saving..." : "Select"}
          </Button>
        </div>
      </div>
    </div>
  );
};
