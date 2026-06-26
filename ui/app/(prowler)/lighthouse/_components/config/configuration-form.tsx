"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import {
  Bot,
  KeyRound,
  Loader2,
  PlugZap,
  Save,
  Sparkles,
  Trash2,
} from "lucide-react";
import { useState } from "react";
import { Controller, useForm } from "react-hook-form";

import {
  createLighthouseV2Configuration,
  deleteLighthouseV2Configuration,
  testLighthouseV2ConfigurationConnection,
  updateLighthouseV2Configuration,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  buildCredentialPayload,
  buildLighthouseV2ConfigFormSchema,
  BUSINESS_CONTEXT_LIMIT,
  EMPTY_FORM_VALUES,
  FEEDBACK_VARIANT,
  type FeedbackState,
  getConnectionStatus,
  getFormDefaults,
  type LighthouseV2ConfigFormValues,
  trimToNullable,
} from "@/app/(prowler)/lighthouse/_lib/config";
import { formatLastChecked } from "@/app/(prowler)/lighthouse/_lib/format";
import {
  type LighthouseV2Configuration,
  type LighthouseV2ConfigurationInput,
  type LighthouseV2ConfigurationUpdateInput,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
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

import { ConfigurationSection } from "./configuration-section";
import { CredentialFields } from "./credential-fields";
import { ProviderIcon } from "./provider-icon";
import { StatusBadge } from "./status-badge";

export function LighthouseV2ConfigurationForm({
  configuration,
  models,
  onConfigurationDeleted,
  onConfigurationSaved,
  onConfigurationTested,
  onFeedback,
  provider,
}: {
  configuration?: LighthouseV2Configuration;
  models: LighthouseV2SupportedModel[];
  onConfigurationDeleted: (configurationId: string) => void;
  onConfigurationSaved: (configuration: LighthouseV2Configuration) => void;
  onConfigurationTested: (configuration: LighthouseV2Configuration) => void;
  onFeedback: (feedback: FeedbackState | null) => void;
  provider: LighthouseV2SupportedProvider;
}) {
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
        title: "Connection check failed",
        description: result.error,
        variant: FEEDBACK_VARIANT.ERROR,
      });
      return;
    }

    onConfigurationTested(result.data);
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
    <section className="min-w-0">
      <div className="border-border-neutral-secondary flex flex-col gap-4 border-b px-4 py-6 md:flex-row md:items-start md:justify-between md:px-5">
        <div className="flex min-w-0 gap-3">
          <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-12 shrink-0 items-center justify-center rounded-[10px] border">
            <ProviderIcon
              provider={providerType}
              className="text-text-neutral-secondary size-6"
            />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-text-neutral-primary text-xl font-semibold">
                {provider.name}
              </h3>
              <StatusBadge status={status} />
              <span className="text-text-neutral-tertiary text-xs">
                {formatLastChecked(configuration?.connectionLastCheckedAt)}
              </span>
            </div>
            <p className="text-text-neutral-secondary mt-1 max-w-2xl text-sm">
              {configuration
                ? "Stored provider configuration. Rotate credentials only when needed."
                : "Create provider configuration before Lighthouse AI can use this model family."}
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
            {testing ? "Testing connection…" : "Test connection"}
          </Button>
        </div>
      </div>

      <form
        className="grid gap-0"
        onSubmit={form.handleSubmit(handleSave)}
        noValidate
      >
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
        </ConfigurationSection>

        <ConfigurationSection
          icon={<Bot className="size-4" />}
          title="Business context"
          description="Short operational context Lighthouse AI should consider while answering."
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

        <div className="flex flex-col gap-4 px-4 py-6 sm:flex-row sm:items-center sm:justify-between md:px-5">
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
        title="Delete Lighthouse AI configuration?"
        description={`This removes ${provider.name} from Lighthouse AI. Existing chat history stays available, but this provider cannot be used until configured again.`}
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
