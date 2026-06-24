"use client";

import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  PlugZap,
  Save,
  Trash2,
} from "lucide-react";
import { type ReactNode, useState } from "react";

import {
  createLighthouseV2Configuration,
  deleteLighthouseV2Configuration,
  testLighthouseV2ConfigurationConnection,
  updateLighthouseV2Configuration,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { Input } from "@/components/shadcn/input/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { cn } from "@/lib/utils";
import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2Credentials,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/types/lighthouse-v2";

interface LighthouseV2ConfigPageProps {
  configurations: LighthouseV2Configuration[];
  providers: LighthouseV2SupportedProvider[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  error?: string;
}

const PROVIDER_ACCENT_CLASS = {
  openai: "border-border-neutral-secondary",
  bedrock: "border-border-warning",
  "openai-compatible": "border-border-info",
} as const satisfies Record<LighthouseV2ProviderType, string>;

const EMPTY_CREDENTIALS = {
  apiKey: "",
  awsAccessKeyId: "",
  awsSecretAccessKey: "",
  awsRegionName: "",
} as const;

export function LighthouseV2ConfigPage({
  configurations,
  providers,
  modelsByProvider,
  error,
}: LighthouseV2ConfigPageProps) {
  const [localConfigurations, setLocalConfigurations] =
    useState(configurations);
  const [selectedProvider, setSelectedProvider] =
    useState<LighthouseV2ProviderType>(providers[0]?.id ?? "openai");
  const [credentials, setCredentials] = useState(EMPTY_CREDENTIALS);
  const [baseUrl, setBaseUrl] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [businessContext, setBusinessContext] = useState(
    configurations[0]?.businessContext ?? "",
  );
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(error ?? null);

  const selectedConfig = localConfigurations.find(
    (config) => config.providerType === selectedProvider,
  );
  const selectedModels = modelsByProvider[selectedProvider] ?? [];
  const selectedProviderName =
    providers.find((provider) => provider.id === selectedProvider)?.name ??
    selectedProvider;

  const handleProviderSelect = (provider: LighthouseV2ProviderType) => {
    const nextConfig = localConfigurations.find(
      (config) => config.providerType === provider,
    );
    setSelectedProvider(provider);
    setCredentials(EMPTY_CREDENTIALS);
    setBaseUrl(nextConfig?.baseUrl ?? "");
    setDefaultModel(nextConfig?.defaultModel ?? "");
    setBusinessContext(nextConfig?.businessContext ?? businessContext);
    setFeedback(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setFeedback(null);
    const credentialPayload = buildCredentialPayload(
      selectedProvider,
      credentials,
    );
    const result = selectedConfig
      ? await updateLighthouseV2Configuration(selectedConfig.id, {
          credentials: credentialPayload,
          baseUrl: baseUrl || null,
          defaultModel: defaultModel || null,
          businessContext,
        })
      : await createLighthouseV2Configuration({
          providerType: selectedProvider,
          credentials: credentialPayload,
          baseUrl: baseUrl || null,
          defaultModel: defaultModel || null,
          businessContext,
        });
    setSaving(false);

    if ("error" in result) {
      setFeedback(result.error);
      return;
    }

    setLocalConfigurations((current) => [
      ...current.filter((config) => config.id !== result.data.id),
      result.data,
    ]);
    setFeedback("Configuration saved.");
  };

  const handleTestConnection = async () => {
    if (!selectedConfig) return;
    setTesting(true);
    setFeedback(null);
    const result = await testLighthouseV2ConfigurationConnection(
      selectedConfig.id,
    );
    setTesting(false);
    setFeedback(
      "error" in result
        ? result.error
        : "Connection check started. Refresh this page after it completes.",
    );
  };

  const handleDelete = async () => {
    if (!selectedConfig) return;
    setDeleting(true);
    setFeedback(null);
    const result = await deleteLighthouseV2Configuration(selectedConfig.id);
    setDeleting(false);
    if ("error" in result) {
      setFeedback(result.error);
      return;
    }
    setLocalConfigurations((current) =>
      current.filter((config) => config.id !== selectedConfig.id),
    );
    setFeedback("Configuration removed.");
  };

  return (
    <div className="grid h-full min-h-0 gap-4 xl:grid-cols-[360px_1fr]">
      <section className="flex min-h-0 flex-col gap-3">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
          {providers.map((provider) => {
            const config = localConfigurations.find(
              (item) => item.providerType === provider.id,
            );
            const active = provider.id === selectedProvider;
            return (
              <button
                key={provider.id}
                type="button"
                onClick={() => handleProviderSelect(provider.id)}
                className="text-left"
              >
                <Card
                  variant="inner"
                  className={cn(
                    "min-h-[116px] gap-3 rounded-[8px] transition-colors",
                    PROVIDER_ACCENT_CLASS[provider.id],
                    active && "ring-border-input-primary-press ring-1",
                  )}
                >
                  <CardHeader className="mb-0 flex-row items-start justify-between gap-3">
                    <div>
                      <CardTitle className="text-base">
                        {provider.name}
                      </CardTitle>
                      <p className="text-text-neutral-secondary mt-2 text-xs">
                        {config?.defaultModel ?? "No default model"}
                      </p>
                    </div>
                    <ConnectionBadge connected={config?.connected ?? null} />
                  </CardHeader>
                </Card>
              </button>
            );
          })}
        </div>
      </section>

      <Card variant="inner" className="min-h-0 rounded-[8px]">
        <CardHeader className="mb-0">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>{selectedProviderName}</CardTitle>
              <p className="text-text-neutral-secondary mt-2 text-sm">
                {selectedConfig ? "Stored configuration" : "New configuration"}
              </p>
            </div>
            <ConnectionBadge connected={selectedConfig?.connected ?? null} />
          </div>
        </CardHeader>
        <CardContent className="grid gap-5">
          <CredentialFields
            provider={selectedProvider}
            credentials={credentials}
            baseUrl={baseUrl}
            onCredentialsChange={setCredentials}
            onBaseUrlChange={setBaseUrl}
          />

          <div className="grid gap-2">
            <label
              className="text-sm font-medium"
              htmlFor="lighthouse-v2-model"
            >
              Default model
            </label>
            <Select value={defaultModel} onValueChange={setDefaultModel}>
              <SelectTrigger id="lighthouse-v2-model">
                <SelectValue placeholder="Select model" />
              </SelectTrigger>
              <SelectContent>
                {selectedModels.map((model) => (
                  <SelectItem key={model.id} value={model.id}>
                    {model.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2">
            <label
              className="text-sm font-medium"
              htmlFor="lighthouse-v2-business-context"
            >
              Business context
            </label>
            <Textarea
              id="lighthouse-v2-business-context"
              value={businessContext}
              onChange={(event) => setBusinessContext(event.target.value)}
              textareaSize="lg"
            />
          </div>

          {feedback && (
            <div className="border-border-neutral-secondary bg-bg-neutral-secondary rounded-[8px] border px-3 py-2 text-sm">
              {feedback}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="animate-spin" /> : <Save />}
              Save
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={handleTestConnection}
              disabled={!selectedConfig || testing}
            >
              {testing ? <Loader2 className="animate-spin" /> : <PlugZap />}
              Test
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={handleDelete}
              disabled={!selectedConfig || deleting}
            >
              {deleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
              Delete
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function CredentialFields({
  provider,
  credentials,
  baseUrl,
  onCredentialsChange,
  onBaseUrlChange,
}: {
  provider: LighthouseV2ProviderType;
  credentials: typeof EMPTY_CREDENTIALS;
  baseUrl: string;
  onCredentialsChange: (credentials: typeof EMPTY_CREDENTIALS) => void;
  onBaseUrlChange: (value: string) => void;
}) {
  const updateCredential = (
    key: keyof typeof EMPTY_CREDENTIALS,
    value: string,
  ) => onCredentialsChange({ ...credentials, [key]: value });

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {(provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
        provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE ||
        credentials.apiKey) && (
        <Field label="API key" htmlFor="lighthouse-v2-api-key">
          <Input
            id="lighthouse-v2-api-key"
            type="password"
            value={credentials.apiKey}
            onChange={(event) => updateCredential("apiKey", event.target.value)}
          />
        </Field>
      )}

      {provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE && (
        <Field label="Base URL" htmlFor="lighthouse-v2-base-url">
          <Input
            id="lighthouse-v2-base-url"
            value={baseUrl}
            onChange={(event) => onBaseUrlChange(event.target.value)}
          />
        </Field>
      )}

      {provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK && (
        <>
          <Field label="AWS access key ID" htmlFor="lighthouse-v2-access-key">
            <Input
              id="lighthouse-v2-access-key"
              type="password"
              value={credentials.awsAccessKeyId}
              onChange={(event) =>
                updateCredential("awsAccessKeyId", event.target.value)
              }
            />
          </Field>
          <Field
            label="AWS secret access key"
            htmlFor="lighthouse-v2-secret-key"
          >
            <Input
              id="lighthouse-v2-secret-key"
              type="password"
              value={credentials.awsSecretAccessKey}
              onChange={(event) =>
                updateCredential("awsSecretAccessKey", event.target.value)
              }
            />
          </Field>
          <Field label="AWS region" htmlFor="lighthouse-v2-region">
            <Input
              id="lighthouse-v2-region"
              value={credentials.awsRegionName}
              onChange={(event) =>
                updateCredential("awsRegionName", event.target.value)
              }
            />
          </Field>
        </>
      )}
    </div>
  );
}

function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
    </div>
  );
}

function ConnectionBadge({ connected }: { connected: boolean | null }) {
  if (connected === true) {
    return (
      <Badge variant="success" className="gap-1">
        <CheckCircle2 className="size-3.5" />
        Connected
      </Badge>
    );
  }

  if (connected === false) {
    return (
      <Badge variant="destructive" className="gap-1">
        <AlertCircle className="size-3.5" />
        Failed
      </Badge>
    );
  }

  return <Badge variant="outline">Not tested</Badge>;
}

function buildCredentialPayload(
  provider: LighthouseV2ProviderType,
  credentials: typeof EMPTY_CREDENTIALS,
): LighthouseV2Credentials {
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) {
    if (credentials.apiKey) {
      return {
        api_key: credentials.apiKey,
        aws_region_name: credentials.awsRegionName,
      };
    }
    return {
      aws_access_key_id: credentials.awsAccessKeyId,
      aws_secret_access_key: credentials.awsSecretAccessKey,
      aws_region_name: credentials.awsRegionName,
    };
  }

  return { api_key: credentials.apiKey };
}
