"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  createLighthouseProvider,
  getLighthouseProviderByType,
  updateLighthouseProviderByType,
} from "@/actions/lighthouse/lighthouse";
import { FormButtons } from "@/components/ui/form";
import type { LighthouseProvider } from "@/types/lighthouse";

import { getMainFields, getProviderConfig } from "./llm-provider-registry";
import {
  isProviderFormValid,
  shouldTestConnection,
  testAndRefreshModels,
} from "./llm-provider-utils";

interface ConnectLLMProviderProps {
  provider: LighthouseProvider;
  mode?: string;
}

type FormData = Record<string, string>;
type Status = "idle" | "connecting" | "verifying" | "loading-models";

export const ConnectLLMProvider = ({
  provider,
  mode = "create",
}: ConnectLLMProviderProps) => {
  const router = useRouter();
  const providerConfig = getProviderConfig(provider);
  const isEditMode = mode === "edit";

  const [formData, setFormData] = useState<FormData>({});
  const [existingProviderId, setExistingProviderId] = useState<string | null>(
    null,
  );
  const [status, setStatus] = useState<Status>("idle");
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch existing provider ID in edit mode
  useEffect(() => {
    if (!isEditMode || !providerConfig) return;

    const fetchProvider = async () => {
      setIsFetching(true);
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

    fetchProvider();
  }, [isEditMode, provider, providerConfig]);

  const buildPayload = (): Record<string, any> => {
    if (!providerConfig) return {};

    const credentials: Record<string, string> = {};
    const otherFields: Record<string, string> = {};

    providerConfig.fields.forEach((field) => {
      if (formData[field.name]) {
        if (field.requiresConnectionTest) {
          credentials[field.name] = formData[field.name];
        } else {
          otherFields[field.name] = formData[field.name];
        }
      }
    });

    return {
      ...(Object.keys(credentials).length > 0 && { credentials }),
      ...otherFields,
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!providerConfig) return;

    setStatus("connecting");
    setError(null);

    try {
      let providerId: string;
      const payload = buildPayload();

      // Update if we have an existing provider, otherwise create
      if (existingProviderId) {
        if (Object.keys(payload).length > 0) {
          await updateLighthouseProviderByType(provider, payload);
        }
        providerId = existingProviderId;
      } else {
        const result = await createLighthouseProvider({
          provider_type: provider,
          credentials: payload.credentials || {},
          ...(payload.base_url && { base_url: payload.base_url }),
        });

        if (result.errors) {
          throw new Error(
            result.errors[0]?.detail || "Failed to create provider",
          );
        }
        if (!result.data?.id) {
          throw new Error("Failed to create provider");
        }

        providerId = result.data.id;
        setExistingProviderId(providerId);
      }

      // Test connection if credentials provided
      if (shouldTestConnection(provider, formData)) {
        setStatus("verifying");
        await testAndRefreshModels(providerId);
        setStatus("loading-models");
      }

      // Navigate to model selection on success
      router.push(
        `/lighthouse/config/select-model?provider=${provider}${isEditMode ? "&mode=edit" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStatus("idle");
    }
  };

  const handleFieldChange = (fieldName: string, value: string) => {
    setFormData((prev) => ({ ...prev, [fieldName]: value }));
    if (error) setError(null);
  };

  const getSubmitText = () => {
    if (error && existingProviderId) return "Retry Connection";
    return isEditMode ? "Continue" : "Connect";
  };

  const getLoadingText = () => {
    if (status === "idle") return "Connecting...";

    const statusText: Record<Exclude<Status, "idle">, string> = {
      connecting: "Connecting...",
      verifying: "Verifying...",
      "loading-models": "Loading models...",
    };
    return statusText[status] || "Connecting...";
  };

  if (!providerConfig) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-text-error text-sm">
          Provider configuration not found: {provider}
        </div>
      </div>
    );
  }

  if (isFetching) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-text-neutral-secondary text-sm">
          Loading provider configuration...
        </div>
      </div>
    );
  }

  const mainFields = getMainFields(provider);
  const isFormValid = isProviderFormValid(provider, formData, isEditMode);
  const isLoading = status !== "idle";

  return (
    <div className="flex w-full flex-col gap-6">
      <div>
        <h2 className="mb-2 text-xl font-semibold">
          {isEditMode
            ? `Update ${providerConfig.name}`
            : `Connect to ${providerConfig.name}`}
        </h2>
        <p className="text-text-neutral-secondary text-sm">
          {isEditMode
            ? `Update your API credentials or settings for ${providerConfig.name}.`
            : `Enter your API credentials to connect to ${providerConfig.name}.`}
        </p>
      </div>

      {error && (
        <div className="border-border-error-primary bg-bg-fail-secondary rounded-lg border p-4">
          <p className="text-text-error text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {mainFields.map((field) => (
          <div key={field.name}>
            <label
              htmlFor={field.name}
              className="mb-2 block text-sm font-medium"
            >
              {field.label}{" "}
              {!isEditMode && field.required && (
                <span className="text-text-error">*</span>
              )}
              {isEditMode && (
                <span className="text-text-neutral-tertiary text-xs">
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
              className="border-border-neutral-primary bg-bg-neutral-primary w-full rounded-lg border px-3 py-2"
            />
          </div>
        ))}

        <FormButtons
          onCancel={() => router.push("/lighthouse/config")}
          submitText={getSubmitText()}
          loadingText={getLoadingText()}
          isDisabled={!isFormValid || isLoading}
        />
      </form>
    </div>
  );
};
