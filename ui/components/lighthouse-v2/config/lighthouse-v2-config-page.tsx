"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import {
  AlertCircle,
  Bot,
  CheckCircle2,
  CircleDashed,
  Cloud,
  DatabaseZap,
  KeyRound,
  Loader2,
  PlugZap,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type ReactNode, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import {
  createLighthouseV2Configuration,
  deleteLighthouseV2Configuration,
  testLighthouseV2ConfigurationConnection,
  updateLighthouseV2Configuration,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
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
  type LighthouseV2ConfigurationInput,
  type LighthouseV2ConfigurationUpdateInput,
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

const BUSINESS_CONTEXT_LIMIT = 1000;

const CONNECTION_STATUS = {
  CONNECTED: "connected",
  FAILED: "failed",
  NOT_TESTED: "not-tested",
} as const;

type ConnectionStatus =
  (typeof CONNECTION_STATUS)[keyof typeof CONNECTION_STATUS];

const FEEDBACK_VARIANT = {
  ERROR: "error",
  SUCCESS: "success",
  INFO: "info",
} as const;

type FeedbackVariant = (typeof FEEDBACK_VARIANT)[keyof typeof FEEDBACK_VARIANT];

interface FeedbackState {
  title: string;
  description?: string;
  variant: FeedbackVariant;
  showRefreshStatus?: boolean;
}

const lighthouseV2ConfigFormSchemaBase = z.object({
  apiKey: z.string(),
  awsAccessKeyId: z.string(),
  awsSecretAccessKey: z.string(),
  awsRegionName: z.string(),
  baseUrl: z.string(),
  defaultModel: z.string(),
  businessContext: z.string().max(BUSINESS_CONTEXT_LIMIT, {
    error: "Business context cannot exceed 1000 characters.",
  }),
});

type LighthouseV2ConfigFormValues = z.infer<
  typeof lighthouseV2ConfigFormSchemaBase
>;

const EMPTY_FORM_VALUES: LighthouseV2ConfigFormValues = {
  apiKey: "",
  awsAccessKeyId: "",
  awsSecretAccessKey: "",
  awsRegionName: "",
  baseUrl: "",
  defaultModel: "",
  businessContext: "",
};

export function LighthouseV2ConfigPage({
  configurations,
  providers,
  modelsByProvider,
  error,
}: LighthouseV2ConfigPageProps) {
  const router = useRouter();
  const [localConfigurations, setLocalConfigurations] =
    useState(configurations);
  const [selectedProvider, setSelectedProvider] =
    useState<LighthouseV2ProviderType>(providers[0]?.id ?? "openai");
  const [feedback, setFeedback] = useState<FeedbackState | null>(
    error
      ? {
          title: "Configuration unavailable",
          description: error,
          variant: FEEDBACK_VARIANT.ERROR,
        }
      : null,
  );

  const selectedConfig = localConfigurations.find(
    (config) => config.providerType === selectedProvider,
  );
  const selectedProviderDefinition =
    providers.find((provider) => provider.id === selectedProvider) ??
    providers[0];
  const selectedModels =
    selectedProviderDefinition &&
    modelsByProvider[selectedProviderDefinition.id]
      ? modelsByProvider[selectedProviderDefinition.id]
      : [];
  const readiness = getReadinessSummary(providers, localConfigurations);

  const handleConfigurationSaved = (
    configuration: LighthouseV2Configuration,
  ) => {
    setLocalConfigurations((current) => [
      ...current.filter((config) => config.id !== configuration.id),
      configuration,
    ]);
    setSelectedProvider(configuration.providerType);
    setFeedback({
      title: "Configuration saved.",
      description: "Lighthouse can use this provider after it tests cleanly.",
      variant: FEEDBACK_VARIANT.SUCCESS,
    });
  };

  const handleConfigurationDeleted = (configurationId: string) => {
    setLocalConfigurations((current) =>
      current.filter((config) => config.id !== configurationId),
    );
    setFeedback({
      title: "Configuration removed.",
      description: "This provider is no longer available for Lighthouse.",
      variant: FEEDBACK_VARIANT.INFO,
    });
  };

  if (providers.length === 0 || !selectedProviderDefinition) {
    return <LighthouseV2EmptyState error={error} />;
  }

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5">
      <LighthouseV2ReadinessHeader readiness={readiness} />

      {feedback && (
        <LighthouseV2Feedback
          feedback={feedback}
          onRefreshStatus={() => router.refresh()}
          onClose={() => setFeedback(null)}
        />
      )}

      <div className="grid min-h-0 gap-5 xl:grid-cols-[340px_minmax(0,1fr)]">
        <LighthouseV2ProviderRail
          configurations={localConfigurations}
          providers={providers}
          selectedProvider={selectedProvider}
          onSelectProvider={(provider) => {
            setSelectedProvider(provider);
            setFeedback(null);
          }}
        />

        <LighthouseV2ConfigurationForm
          key={selectedProvider}
          configuration={selectedConfig}
          models={selectedModels}
          provider={selectedProviderDefinition}
          onConfigurationSaved={handleConfigurationSaved}
          onConfigurationDeleted={handleConfigurationDeleted}
          onFeedback={setFeedback}
        />
      </div>
    </div>
  );
}

function LighthouseV2ReadinessHeader({
  readiness,
}: {
  readiness: ReadinessSummary;
}) {
  const ready =
    readiness.connected > 0
      ? "Ready for chat"
      : readiness.failed > 0
        ? "Needs attention"
        : "Setup required";

  return (
    <section className="border-border-neutral-secondary bg-bg-neutral-secondary rounded-[12px] border px-4 py-4 md:px-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-3">
          <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-11 shrink-0 items-center justify-center rounded-[10px] border">
            <ShieldCheck className="text-text-success-primary size-5" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-text-neutral-primary text-lg font-semibold">
                Lighthouse readiness
              </h2>
              <Badge variant={readiness.connected > 0 ? "success" : "warning"}>
                {ready}
              </Badge>
            </div>
            <p className="text-text-neutral-secondary mt-1 max-w-3xl text-sm">
              Manage the model providers Lighthouse can use for Cloud analysis.
              Connected providers are available in chat; failed or untested
              providers stay blocked until tested cleanly.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 sm:min-w-[360px]">
          <ReadinessMetric
            label="connected"
            value={readiness.connected}
            status={CONNECTION_STATUS.CONNECTED}
          />
          <ReadinessMetric
            label="failed"
            value={readiness.failed}
            status={CONNECTION_STATUS.FAILED}
          />
          <ReadinessMetric
            label="not tested"
            value={readiness.notTested}
            status={CONNECTION_STATUS.NOT_TESTED}
          />
        </div>
      </div>
    </section>
  );
}

function ReadinessMetric({
  label,
  value,
  status,
}: {
  label: string;
  value: number;
  status: ConnectionStatus;
}) {
  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-[10px] border px-3 py-2">
      <div className="flex items-center gap-2">
        <StatusDot status={status} />
        <span className="text-text-neutral-primary text-lg leading-none font-semibold">
          {value}
        </span>
      </div>
      <p className="text-text-neutral-secondary mt-1 text-xs">
        {value} {label}
      </p>
    </div>
  );
}

function LighthouseV2Feedback({
  feedback,
  onClose,
  onRefreshStatus,
}: {
  feedback: FeedbackState;
  onClose: () => void;
  onRefreshStatus: () => void;
}) {
  const Icon =
    feedback.variant === FEEDBACK_VARIANT.ERROR
      ? AlertCircle
      : feedback.variant === FEEDBACK_VARIANT.SUCCESS
        ? CheckCircle2
        : RefreshCw;

  return (
    <Alert variant={feedback.variant} onClose={onClose}>
      <Icon className="size-4" />
      <AlertTitle>{feedback.title}</AlertTitle>
      <AlertDescription>
        {feedback.description && <p>{feedback.description}</p>}
        {feedback.showRefreshStatus && (
          <Button
            type="button"
            variant="link"
            size="link-sm"
            className="h-auto p-0"
            onClick={onRefreshStatus}
          >
            <RefreshCw className="size-3.5" />
            Refresh status
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}

function LighthouseV2ProviderRail({
  configurations,
  providers,
  selectedProvider,
  onSelectProvider,
}: {
  configurations: LighthouseV2Configuration[];
  providers: LighthouseV2SupportedProvider[];
  selectedProvider: LighthouseV2ProviderType;
  onSelectProvider: (provider: LighthouseV2ProviderType) => void;
}) {
  return (
    <aside className="flex min-w-0 flex-col gap-3">
      <div className="flex items-center justify-between gap-3 px-1">
        <div>
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Providers
          </h3>
          <p className="text-text-neutral-secondary text-xs">
            Choose provider to configure
          </p>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        {providers.map((provider) => {
          const config = configurations.find(
            (item) => item.providerType === provider.id,
          );
          const active = provider.id === selectedProvider;
          const status = getConnectionStatus(config);
          const Icon = getProviderIcon(provider.id);

          return (
            <button
              key={provider.id}
              type="button"
              aria-label={provider.name}
              aria-pressed={active}
              onClick={() => onSelectProvider(provider.id)}
              className={cn(
                "border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary group flex min-w-0 items-start gap-3 rounded-[12px] border p-3 text-left transition-colors",
                active &&
                  "border-border-input-primary-press bg-bg-neutral-tertiary ring-border-input-primary-press ring-1",
              )}
            >
              <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-10 shrink-0 items-center justify-center rounded-[9px] border">
                <Icon className="text-text-neutral-secondary size-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex min-w-0 items-center justify-between gap-2">
                  <span className="text-text-neutral-primary truncate text-sm font-medium">
                    {provider.name}
                  </span>
                  <StatusBadge status={status} />
                </div>
                <p className="text-text-neutral-secondary mt-1 truncate text-xs">
                  {config?.defaultModel || "No default model"}
                </p>
                <p className="text-text-neutral-tertiary mt-1 text-xs">
                  {formatLastChecked(config?.connectionLastCheckedAt)}
                </p>
              </div>
            </button>
          );
        })}
      </div>
    </aside>
  );
}

function LighthouseV2ConfigurationForm({
  configuration,
  models,
  onConfigurationDeleted,
  onConfigurationSaved,
  onFeedback,
  provider,
}: {
  configuration?: LighthouseV2Configuration;
  models: LighthouseV2SupportedModel[];
  onConfigurationDeleted: (configurationId: string) => void;
  onConfigurationSaved: (configuration: LighthouseV2Configuration) => void;
  onFeedback: (feedback: FeedbackState | null) => void;
  provider: LighthouseV2SupportedProvider;
}) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const providerType = provider.id;
  const hasConfiguration = Boolean(configuration);
  const form = useForm<LighthouseV2ConfigFormValues>({
    resolver: zodResolver(
      buildLighthouseV2ConfigFormSchema(providerType, hasConfiguration),
    ),
    defaultValues: getFormDefaults(configuration),
    mode: "onSubmit",
  });
  const businessContext = form.watch("businessContext");
  const selectedModel = form.watch("defaultModel");
  const selectedModelDetails = models.find(
    (model) => model.id === selectedModel,
  );
  const status = getConnectionStatus(configuration);

  const handleSave = async (values: LighthouseV2ConfigFormValues) => {
    setSaving(true);
    onFeedback(null);

    const credentials = buildCredentialPayload(
      providerType,
      values,
      hasConfiguration,
    );

    const basePayload = {
      baseUrl: trimToNullable(values.baseUrl),
      defaultModel: trimToNullable(values.defaultModel),
      businessContext: values.businessContext,
    };

    const result = configuration
      ? await updateLighthouseV2Configuration(configuration.id, {
          ...basePayload,
          ...(credentials ? { credentials } : {}),
        } satisfies LighthouseV2ConfigurationUpdateInput)
      : await createLighthouseV2Configuration({
          providerType,
          credentials:
            credentials as LighthouseV2ConfigurationInput["credentials"],
          ...basePayload,
        });

    setSaving(false);

    if ("error" in result) {
      onFeedback({
        title: "Configuration not saved",
        description: result.error,
        variant: FEEDBACK_VARIANT.ERROR,
      });
      return;
    }

    form.reset(getFormDefaults(result.data));
    onConfigurationSaved(result.data);
  };

  const handleTestConnection = async () => {
    if (!configuration) return;

    setTesting(true);
    onFeedback(null);
    const result = await testLighthouseV2ConfigurationConnection(
      configuration.id,
    );
    setTesting(false);

    if ("error" in result) {
      onFeedback({
        title: "Connection check failed to start",
        description: result.error,
        variant: FEEDBACK_VARIANT.ERROR,
      });
      return;
    }

    onFeedback({
      title: "Connection check started.",
      description:
        "The backend is validating this provider. Refresh status when the task finishes.",
      variant: FEEDBACK_VARIANT.INFO,
      showRefreshStatus: true,
    });
  };

  const handleDelete = async () => {
    if (!configuration) return;

    setDeleting(true);
    const result = await deleteLighthouseV2Configuration(configuration.id);
    setDeleting(false);

    if ("error" in result) {
      onFeedback({
        title: "Configuration not removed",
        description: result.error,
        variant: FEEDBACK_VARIANT.ERROR,
      });
      return;
    }

    setDeleteOpen(false);
    form.reset(EMPTY_FORM_VALUES);
    onConfigurationDeleted(configuration.id);
  };

  return (
    <section className="border-border-neutral-secondary bg-bg-neutral-secondary min-w-0 rounded-[12px] border">
      <div className="border-border-neutral-secondary flex flex-col gap-4 border-b px-4 py-4 md:flex-row md:items-start md:justify-between md:px-5">
        <div className="flex min-w-0 gap-3">
          <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-12 shrink-0 items-center justify-center rounded-[10px] border">
            {(() => {
              const Icon = getProviderIcon(providerType);
              return <Icon className="text-text-neutral-secondary size-6" />;
            })()}
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-text-neutral-primary text-xl font-semibold">
                {provider.name}
              </h3>
              <StatusBadge status={status} />
            </div>
            <p className="text-text-neutral-secondary mt-1 max-w-2xl text-sm">
              {configuration
                ? "Stored provider configuration. Rotate credentials only when needed."
                : "Create provider configuration before Lighthouse can use this model family."}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={handleTestConnection}
            disabled={!configuration || testing}
          >
            {testing ? <Loader2 className="animate-spin" /> : <PlugZap />}
            Test connection
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => router.refresh()}
          >
            <RefreshCw />
            Refresh status
          </Button>
        </div>
      </div>

      <form
        className="grid gap-0"
        onSubmit={form.handleSubmit(handleSave)}
        noValidate
      >
        <ConfigurationSection
          icon={<ShieldCheck className="size-4" />}
          title="Connection"
          description="Current backend check result for this provider."
        >
          <ConnectionStatusPanel
            configuration={configuration}
            status={status}
          />
        </ConfigurationSection>

        <ConfigurationSection
          icon={<KeyRound className="size-4" />}
          title="Credentials"
          description={
            configuration
              ? "Leave blank to keep existing credentials."
              : "Credentials are required for new configurations."
          }
        >
          <CredentialFields
            errors={form.formState.errors}
            hasConfiguration={hasConfiguration}
            provider={providerType}
            register={form.register}
          />
        </ConfigurationSection>

        <ConfigurationSection
          icon={<Sparkles className="size-4" />}
          title="Default model"
          description="Model used when chat does not override provider/model for a turn."
        >
          <Controller
            control={form.control}
            name="defaultModel"
            render={({ field }) => (
              <Field>
                <FieldLabel htmlFor="lighthouse-v2-model">
                  Default model
                </FieldLabel>
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  allowDeselect
                >
                  <SelectTrigger id="lighthouse-v2-model">
                    <SelectValue placeholder="Select model" />
                  </SelectTrigger>
                  <SelectContent width="wide">
                    {models.map((model) => (
                      <SelectItem key={model.id} value={model.id}>
                        {model.id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            )}
          />
          <ModelDetails model={selectedModelDetails} />
        </ConfigurationSection>

        <ConfigurationSection
          icon={<Bot className="size-4" />}
          title="Business context"
          description="Short operational context Lighthouse should consider while answering."
        >
          <Field>
            <div className="flex items-center justify-between gap-3">
              <FieldLabel htmlFor="lighthouse-v2-business-context">
                Business context
              </FieldLabel>
              <span
                className={cn(
                  "text-xs",
                  businessContext.length > BUSINESS_CONTEXT_LIMIT
                    ? "text-text-error-primary"
                    : "text-text-neutral-tertiary",
                )}
              >
                {businessContext.length}/{BUSINESS_CONTEXT_LIMIT}
              </span>
            </div>
            <Textarea
              id="lighthouse-v2-business-context"
              textareaSize="lg"
              aria-invalid={Boolean(form.formState.errors.businessContext)}
              placeholder="Example: production AWS accounts, PCI workloads, EU data residency, critical internet-facing services..."
              {...form.register("businessContext")}
            />
            {form.formState.errors.businessContext?.message && (
              <FieldError>
                {form.formState.errors.businessContext.message}
              </FieldError>
            )}
          </Field>
        </ConfigurationSection>

        <div className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between md:px-5">
          <div className="text-text-neutral-secondary text-sm">
            {configuration
              ? "Saving updates may change chat behavior immediately."
              : "Save provider before testing the connection."}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={saving}>
              {saving ? <Loader2 className="animate-spin" /> : <Save />}
              Save
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={() => setDeleteOpen(true)}
              disabled={!configuration || deleting}
            >
              {deleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
              Delete
            </Button>
          </div>
        </div>
      </form>

      <Modal
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Lighthouse configuration?"
        description={`This removes ${provider.name} from Lighthouse. Existing chat history stays available, but this provider cannot be used until configured again.`}
        size="md"
      >
        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => setDeleteOpen(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            onClick={handleDelete}
            disabled={deleting}
          >
            {deleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
            Delete configuration
          </Button>
        </div>
      </Modal>
    </section>
  );
}

function ConfigurationSection({
  children,
  description,
  icon,
  title,
}: {
  children: ReactNode;
  description: string;
  icon: ReactNode;
  title: string;
}) {
  return (
    <section className="border-border-neutral-secondary grid gap-4 border-b px-4 py-5 md:grid-cols-[220px_minmax(0,1fr)] md:px-5">
      <div className="flex gap-3">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-8 shrink-0 items-center justify-center rounded-[8px] border">
          {icon}
        </div>
        <div>
          <h4 className="text-text-neutral-primary text-sm font-semibold">
            {title}
          </h4>
          <p className="text-text-neutral-secondary mt-1 text-sm">
            {description}
          </p>
        </div>
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}

function ConnectionStatusPanel({
  configuration,
  status,
}: {
  configuration?: LighthouseV2Configuration;
  status: ConnectionStatus;
}) {
  const statusText = getConnectionStatusLabel(status);
  const description =
    status === CONNECTION_STATUS.CONNECTED
      ? "Lighthouse can send messages with this provider."
      : status === CONNECTION_STATUS.FAILED
        ? "Connection failed. Review credentials and run another test."
        : "Connection has not been tested yet.";

  return (
    <Alert variant={getAlertVariant(status)}>
      {status === CONNECTION_STATUS.CONNECTED ? (
        <CheckCircle2 className="size-4" />
      ) : status === CONNECTION_STATUS.FAILED ? (
        <AlertCircle className="size-4" />
      ) : (
        <CircleDashed className="size-4" />
      )}
      <AlertTitle>{statusText}</AlertTitle>
      <AlertDescription>
        <p>{description}</p>
        <p>{formatLastChecked(configuration?.connectionLastCheckedAt)}</p>
      </AlertDescription>
    </Alert>
  );
}

function CredentialFields({
  errors,
  hasConfiguration,
  provider,
  register,
}: {
  errors: ReturnType<
    typeof useForm<LighthouseV2ConfigFormValues>
  >["formState"]["errors"];
  hasConfiguration: boolean;
  provider: LighthouseV2ProviderType;
  register: ReturnType<
    typeof useForm<LighthouseV2ConfigFormValues>
  >["register"];
}) {
  return (
    <div className="grid gap-4">
      {hasConfiguration && (
        <p className="text-text-neutral-secondary text-sm">
          Leave blank to keep existing credentials.
        </p>
      )}

      {(provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
        provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE) && (
        <Field>
          <FieldLabel htmlFor="lighthouse-v2-api-key">API key</FieldLabel>
          <Input
            id="lighthouse-v2-api-key"
            type="password"
            autoComplete="off"
            aria-invalid={Boolean(errors.apiKey)}
            {...register("apiKey")}
          />
          {errors.apiKey?.message && (
            <FieldError>{errors.apiKey.message}</FieldError>
          )}
        </Field>
      )}

      {provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE && (
        <Field>
          <FieldLabel htmlFor="lighthouse-v2-base-url">Base URL</FieldLabel>
          <Input
            id="lighthouse-v2-base-url"
            aria-invalid={Boolean(errors.baseUrl)}
            placeholder="https://llm.example.com/v1"
            {...register("baseUrl")}
          />
          {errors.baseUrl?.message && (
            <FieldError>{errors.baseUrl.message}</FieldError>
          )}
        </Field>
      )}

      {provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK && (
        <div className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="lighthouse-v2-access-key">
              AWS access key ID
            </FieldLabel>
            <Input
              id="lighthouse-v2-access-key"
              type="password"
              autoComplete="off"
              aria-invalid={Boolean(errors.awsAccessKeyId)}
              {...register("awsAccessKeyId")}
            />
            {errors.awsAccessKeyId?.message && (
              <FieldError>{errors.awsAccessKeyId.message}</FieldError>
            )}
          </Field>

          <Field>
            <FieldLabel htmlFor="lighthouse-v2-secret-key">
              AWS secret access key
            </FieldLabel>
            <Input
              id="lighthouse-v2-secret-key"
              type="password"
              autoComplete="off"
              aria-invalid={Boolean(errors.awsSecretAccessKey)}
              {...register("awsSecretAccessKey")}
            />
            {errors.awsSecretAccessKey?.message && (
              <FieldError>{errors.awsSecretAccessKey.message}</FieldError>
            )}
          </Field>

          <Field className="md:col-span-2">
            <FieldLabel htmlFor="lighthouse-v2-region">AWS region</FieldLabel>
            <Input
              id="lighthouse-v2-region"
              placeholder="us-east-1"
              aria-invalid={Boolean(errors.awsRegionName)}
              {...register("awsRegionName")}
            />
            {errors.awsRegionName?.message && (
              <FieldError>{errors.awsRegionName.message}</FieldError>
            )}
          </Field>
        </div>
      )}
    </div>
  );
}

function ModelDetails({ model }: { model?: LighthouseV2SupportedModel }) {
  if (!model) {
    return (
      <div className="border-border-neutral-secondary bg-bg-neutral-tertiary mt-3 rounded-[10px] border px-3 py-3">
        <p className="text-text-neutral-secondary text-sm">
          Select a model to see capabilities.
        </p>
      </div>
    );
  }

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-tertiary mt-3 grid gap-3 rounded-[10px] border px-3 py-3 sm:grid-cols-3">
      <CapabilityItem label="Tools" enabled={model.supportsFunctionCalling} />
      <CapabilityItem label="Vision" enabled={model.supportsVision} />
      <CapabilityItem label="Reasoning" enabled={model.supportsReasoning} />
      <div className="text-text-neutral-secondary text-xs sm:col-span-3">
        Input tokens: {formatTokenLimit(model.maxInputTokens)} · Output tokens:{" "}
        {formatTokenLimit(model.maxOutputTokens)}
      </div>
    </div>
  );
}

function CapabilityItem({
  enabled,
  label,
}: {
  enabled: boolean | null;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2 text-sm">
      {enabled ? (
        <CheckCircle2 className="text-text-success-primary size-4" />
      ) : (
        <CircleDashed className="text-text-neutral-tertiary size-4" />
      )}
      <span className="text-text-neutral-primary">{label}</span>
    </div>
  );
}

function LighthouseV2EmptyState({ error }: { error?: string }) {
  return (
    <Card variant="base" padding="lg" className="mx-auto max-w-3xl">
      <CardContent className="flex flex-col items-center gap-4 py-8 text-center">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-14 items-center justify-center rounded-[14px] border">
          <DatabaseZap className="text-text-neutral-secondary size-7" />
        </div>
        <div>
          <h2 className="text-text-neutral-primary text-xl font-semibold">
            No Lighthouse providers available
          </h2>
          <p className="text-text-neutral-secondary mt-2 text-sm">
            Cloud did not return supported providers for Lighthouse
            configuration.
          </p>
        </div>
        {error && (
          <Alert variant="error" className="text-left">
            <AlertCircle className="size-4" />
            <AlertTitle>Configuration unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

function StatusBadge({ status }: { status: ConnectionStatus }) {
  if (status === CONNECTION_STATUS.CONNECTED) {
    return (
      <Badge variant="success">
        <CheckCircle2 />
        Connected
      </Badge>
    );
  }

  if (status === CONNECTION_STATUS.FAILED) {
    return (
      <Badge variant="error">
        <AlertCircle />
        Failed
      </Badge>
    );
  }

  return (
    <Badge variant="outline">
      <CircleDashed />
      Not tested
    </Badge>
  );
}

function StatusDot({ status }: { status: ConnectionStatus }) {
  return (
    <span
      className={cn(
        "size-2 rounded-full",
        status === CONNECTION_STATUS.CONNECTED && "bg-bg-pass",
        status === CONNECTION_STATUS.FAILED && "bg-bg-fail",
        status === CONNECTION_STATUS.NOT_TESTED && "bg-text-neutral-tertiary",
      )}
    />
  );
}

interface ReadinessSummary {
  connected: number;
  failed: number;
  notTested: number;
}

function getReadinessSummary(
  providers: LighthouseV2SupportedProvider[],
  configurations: LighthouseV2Configuration[],
): ReadinessSummary {
  return providers.reduce(
    (summary, provider) => {
      const config = configurations.find(
        (item) => item.providerType === provider.id,
      );
      const status = getConnectionStatus(config);
      if (status === CONNECTION_STATUS.CONNECTED) {
        return { ...summary, connected: summary.connected + 1 };
      }
      if (status === CONNECTION_STATUS.FAILED) {
        return { ...summary, failed: summary.failed + 1 };
      }
      return { ...summary, notTested: summary.notTested + 1 };
    },
    { connected: 0, failed: 0, notTested: 0 },
  );
}

function getConnectionStatus(
  configuration?: LighthouseV2Configuration,
): ConnectionStatus {
  if (configuration?.connected === true) return CONNECTION_STATUS.CONNECTED;
  if (configuration?.connected === false) return CONNECTION_STATUS.FAILED;
  return CONNECTION_STATUS.NOT_TESTED;
}

function getConnectionStatusLabel(status: ConnectionStatus) {
  if (status === CONNECTION_STATUS.CONNECTED) return "Connected";
  if (status === CONNECTION_STATUS.FAILED) return "Failed";
  return "Not tested";
}

function getAlertVariant(status: ConnectionStatus) {
  if (status === CONNECTION_STATUS.CONNECTED) return "success";
  if (status === CONNECTION_STATUS.FAILED) return "error";
  return "info";
}

function getProviderIcon(provider: LighthouseV2ProviderType) {
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) return Cloud;
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE) return Server;
  return Bot;
}

function getFormDefaults(
  configuration?: LighthouseV2Configuration,
): LighthouseV2ConfigFormValues {
  return {
    ...EMPTY_FORM_VALUES,
    baseUrl: configuration?.baseUrl ?? "",
    defaultModel: configuration?.defaultModel ?? "",
    businessContext: configuration?.businessContext ?? "",
  };
}

function buildLighthouseV2ConfigFormSchema(
  provider: LighthouseV2ProviderType,
  hasConfiguration: boolean,
) {
  return lighthouseV2ConfigFormSchemaBase.superRefine((data, ctx) => {
    const apiKey = data.apiKey.trim();

    if (
      provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE &&
      !data.baseUrl.trim()
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base URL is required for OpenAI-compatible providers.",
        path: ["baseUrl"],
      });
    }

    if (
      (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
        provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE) &&
      !hasConfiguration &&
      !apiKey
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "API key is required for new configurations.",
        path: ["apiKey"],
      });
    }

    if (provider !== LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) return;

    const hasAnyBedrockCredential =
      Boolean(data.awsAccessKeyId.trim()) ||
      Boolean(data.awsSecretAccessKey.trim()) ||
      Boolean(data.awsRegionName.trim());
    const shouldRequireBedrockCredentials =
      !hasConfiguration || hasAnyBedrockCredential;

    if (!shouldRequireBedrockCredentials) return;

    if (!data.awsAccessKeyId.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS access key ID is required.",
        path: ["awsAccessKeyId"],
      });
    }
    if (!data.awsSecretAccessKey.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS secret access key is required.",
        path: ["awsSecretAccessKey"],
      });
    }
    if (!data.awsRegionName.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AWS region is required.",
        path: ["awsRegionName"],
      });
    }
  });
}

function buildCredentialPayload(
  provider: LighthouseV2ProviderType,
  values: LighthouseV2ConfigFormValues,
  hasConfiguration: boolean,
): LighthouseV2Credentials | undefined {
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) {
    const hasBedrockCredentials =
      Boolean(values.awsAccessKeyId.trim()) ||
      Boolean(values.awsSecretAccessKey.trim()) ||
      Boolean(values.awsRegionName.trim());

    if (hasConfiguration && !hasBedrockCredentials) return undefined;

    return {
      aws_access_key_id: values.awsAccessKeyId.trim(),
      aws_secret_access_key: values.awsSecretAccessKey.trim(),
      aws_region_name: values.awsRegionName.trim(),
    };
  }

  if (hasConfiguration && !values.apiKey.trim()) return undefined;

  return { api_key: values.apiKey.trim() };
}

function trimToNullable(value: string) {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function formatTokenLimit(value: number | null) {
  return value === null ? "Unknown" : value.toLocaleString();
}

function formatLastChecked(value?: string | null) {
  if (!value) return "Never checked";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Last check unavailable";

  return `Last checked ${date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  })}`;
}
