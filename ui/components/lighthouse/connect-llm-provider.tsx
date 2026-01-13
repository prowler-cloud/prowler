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
  type LLMCredentialsFormData,
  shouldTestConnection,
  testAndRefreshModels,
} from "./llm-provider-utils";

const BEDROCK_CREDENTIAL_MODES = {
  API_KEY: "api_key",
  IAM: "iam",
} as const;

type BedrockCredentialMode =
  (typeof BEDROCK_CREDENTIAL_MODES)[keyof typeof BEDROCK_CREDENTIAL_MODES];

const CONNECTION_STATUS = {
  IDLE: "idle",
  CONNECTING: "connecting",
  VERIFYING: "verifying",
  LOADING_MODELS: "loading-models",
} as const;

type ConnectionStatus =
  (typeof CONNECTION_STATUS)[keyof typeof CONNECTION_STATUS];

const STATUS_MESSAGES: Record<Exclude<ConnectionStatus, "idle">, string> = {
  [CONNECTION_STATUS.CONNECTING]: "Connecting...",
  [CONNECTION_STATUS.VERIFYING]: "Verifying...",
  [CONNECTION_STATUS.LOADING_MODELS]: "Loading models...",
};

interface ConnectLLMProviderProps {
  provider: LighthouseProvider;
  mode?: string;
  initialAuthMode?: BedrockCredentialMode;
}

type FormData = Record<string, string>;

export const ConnectLLMProvider = ({
  provider,
  mode = "create",
  initialAuthMode,
}: ConnectLLMProviderProps) => {
  const router = useRouter();
  const providerConfig = getProviderConfig(provider);
  const isEditMode = mode === "edit";

  const [formData, setFormData] = useState<FormData>({});
  const [existingProviderId, setExistingProviderId] = useState<string | null>(
    null,
  );
  const [status, setStatus] = useState<ConnectionStatus>(
    CONNECTION_STATUS.IDLE,
  );
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bedrockMode, setBedrockMode] = useState<BedrockCredentialMode>(() => {
    if (provider === "bedrock" && mode !== "edit" && initialAuthMode) {
      return initialAuthMode;
    }
    return BEDROCK_CREDENTIAL_MODES.API_KEY;
  });

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

        // For Bedrock, detect existing credential mode (API key vs IAM)
        if (provider === "bedrock") {
          const attributes = (result.data as any)?.attributes;
          const credentials = attributes?.credentials as
            | LLMCredentialsFormData
            | undefined;

          if (credentials) {
            if (credentials.api_key) {
              setBedrockMode(BEDROCK_CREDENTIAL_MODES.API_KEY);
            } else if (
              credentials.access_key_id ||
              credentials.secret_access_key
            ) {
              setBedrockMode(BEDROCK_CREDENTIAL_MODES.IAM);
            }
          }
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsFetching(false);
      }
    };

    fetchProvider();
  }, [isEditMode, provider, providerConfig]);

  const buildBedrockPayload = (): Record<string, any> => {
    const credentials: LLMCredentialsFormData = {};

    if (bedrockMode === BEDROCK_CREDENTIAL_MODES.API_KEY) {
      if (formData.api_key) credentials.api_key = formData.api_key;
      if (formData.region) credentials.region = formData.region;
    } else {
      if (formData.access_key_id) {
        credentials.access_key_id = formData.access_key_id;
      }
      if (formData.secret_access_key) {
        credentials.secret_access_key = formData.secret_access_key;
      }
      if (formData.region) credentials.region = formData.region;
    }

    return Object.keys(credentials).length > 0 ? { credentials } : {};
  };

  const buildGenericPayload = (): Record<string, any> => {
    const credentials: Record<string, string> = {};
    const otherFields: Record<string, string> = {};

    providerConfig?.fields.forEach((field) => {
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

  const buildPayload = (): Record<string, any> => {
    if (!providerConfig) return {};
    return provider === "bedrock"
      ? buildBedrockPayload()
      : buildGenericPayload();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!providerConfig) return;

    setStatus(CONNECTION_STATUS.CONNECTING);
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

      const shouldTestBedrock =
        (bedrockMode === BEDROCK_CREDENTIAL_MODES.API_KEY &&
          !!formData.api_key?.trim()) ||
        (bedrockMode === BEDROCK_CREDENTIAL_MODES.IAM &&
          (!!formData.access_key_id?.trim() ||
            !!formData.secret_access_key?.trim()));

      const shouldTest =
        provider === "bedrock"
          ? shouldTestBedrock
          : shouldTestConnection(provider, formData);

      // Test connection if credentials provided
      if (shouldTest) {
        setStatus(CONNECTION_STATUS.VERIFYING);
        await testAndRefreshModels(providerId);
        setStatus(CONNECTION_STATUS.LOADING_MODELS);
      }

      // Navigate to model selection on success
      router.push(
        `/lighthouse/config/select-model?provider=${provider}${isEditMode ? "&mode=edit" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStatus(CONNECTION_STATUS.IDLE);
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
    if (status === CONNECTION_STATUS.IDLE) {
      return "";
    }
    return (
      STATUS_MESSAGES[status] || STATUS_MESSAGES[CONNECTION_STATUS.CONNECTING]
    );
  };

  const renderFormField = (
    id: string,
    label: string,
    type: string,
    placeholder: string,
    required = true,
  ) => (
    <div>
      <label htmlFor={id} className="mb-2 block text-sm font-medium">
        {label}{" "}
        {!isEditMode && required && <span className="text-text-error">*</span>}
        {isEditMode && (
          <span className="text-text-neutral-tertiary text-xs">
            (leave empty to keep existing)
          </span>
        )}
      </label>
      <input
        id={id}
        type={type}
        value={formData[id] || ""}
        onChange={(e) => handleFieldChange(id, e.target.value)}
        placeholder={
          isEditMode ? `Enter new ${label} or leave empty` : placeholder
        }
        className="border-border-neutral-primary bg-bg-neutral-primary w-full rounded-lg border px-3 py-2"
      />
    </div>
  );

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

  const isBedrockProvider = provider === "bedrock";

  const isBedrockFormValid = (): boolean => {
    if (isEditMode) return true;

    const hasRegion = !!formData.region?.trim();

    if (bedrockMode === BEDROCK_CREDENTIAL_MODES.API_KEY) {
      return !!formData.api_key?.trim() && hasRegion;
    }

    return (
      !!formData.access_key_id?.trim() &&
      !!formData.secret_access_key?.trim() &&
      hasRegion
    );
  };

  const isFormValid = isBedrockProvider
    ? isBedrockFormValid()
    : isProviderFormValid(provider, formData, isEditMode);
  const isLoading = status !== CONNECTION_STATUS.IDLE;

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
        {isBedrockProvider ? (
          <>
            {bedrockMode === BEDROCK_CREDENTIAL_MODES.API_KEY && (
              <div className="border-border-warning-primary bg-bg-warning-secondary rounded-lg border p-4">
                <p className="text-text-warning text-sm font-medium">
                  Recommended only for exploration of Amazon Bedrock.
                </p>
                <p className="text-text-warning mt-1 text-xs">
                  Please ensure you&apos;re using long-term Bedrock API keys.
                </p>
              </div>
            )}
            {bedrockMode === BEDROCK_CREDENTIAL_MODES.API_KEY ? (
              <>
                {renderFormField(
                  "api_key",
                  "API key (long-term)",
                  "password",
                  "Enter your long-term API key",
                )}
                {renderFormField(
                  "region",
                  "AWS region",
                  "text",
                  "Enter the AWS region",
                )}
              </>
            ) : (
              <>
                {renderFormField(
                  "access_key_id",
                  "AWS access key ID",
                  "password",
                  "Enter the AWS Access Key ID",
                )}
                {renderFormField(
                  "secret_access_key",
                  "AWS secret access key",
                  "password",
                  "Enter the AWS Secret Access Key",
                )}
                {renderFormField(
                  "region",
                  "AWS region",
                  "text",
                  "Enter the AWS Region",
                )}
              </>
            )}
          </>
        ) : (
          mainFields.map((field) => (
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
                    ? `Enter new ${field.label} or leave empty`
                    : field.placeholder
                }
                className="border-border-neutral-primary bg-bg-neutral-primary w-full rounded-lg border px-3 py-2"
              />
            </div>
          ))
        )}

        <FormButtons
          onCancel={() => router.push("/lighthouse/config")}
          submitText={isLoading ? getLoadingText() : getSubmitText()}
          loadingText={getLoadingText()}
          isDisabled={!isFormValid || isLoading}
        />
      </form>
    </div>
  );
};
