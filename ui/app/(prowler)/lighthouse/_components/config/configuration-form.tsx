"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound, Loader2, PlugZap, Save, Trash2 } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";

import {
  createLighthouseV2Configuration,
  deleteLighthouseV2Configuration,
  testLighthouseV2ConfigurationConnection,
  updateLighthouseV2Configuration,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  buildCredentialPayload,
  buildLighthouseV2ConfigFormSchema,
  buildLighthouseV2ConfigurationInput,
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
  type LighthouseV2ConfigurationUpdateInput,
  type LighthouseV2Credentials,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { Modal } from "@/components/shadcn/modal";

import { ConfigurationSection } from "./configuration-section";
import { CredentialFields } from "./credential-fields";
import { ProviderIcon } from "./provider-icon";
import { StatusBadge } from "./status-badge";

export function LighthouseV2ConfigurationForm({
  configuration,
  onConfigurationDeleted,
  onConfigurationSaved,
  onConfigurationTested,
  onFeedback,
  provider,
}: {
  configuration?: LighthouseV2Configuration;
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
  const status = getConnectionStatus(configuration);

  const runConnectionTest = async (configurationId: string) => {
    setTesting(true);
    onFeedback(null);

    try {
      const result =
        await testLighthouseV2ConfigurationConnection(configurationId);

      if ("error" in result) {
        onFeedback({
          title: "Connection check failed",
          description: result.error,
          variant: FEEDBACK_VARIANT.ERROR,
        });
        return;
      }

      onConfigurationTested(result.data);
    } catch {
      onFeedback({
        title: "Connection check failed",
        description: "Something went wrong while testing. Please try again.",
        variant: FEEDBACK_VARIANT.ERROR,
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async (values: LighthouseV2ConfigFormValues) => {
    setSaving(true);
    onFeedback(null);

    const credentials = buildCredentialPayload(
      providerType,
      values,
      hasConfiguration,
    );
    const baseUrl = trimToNullable(values.baseUrl);
    const shouldTestAfterSave =
      !configuration ||
      Boolean(credentials) ||
      baseUrl !== (configuration.baseUrl ?? null);

    try {
      const result = configuration
        ? await updateLighthouseV2Configuration(configuration.id, {
            baseUrl,
            ...(credentials ? { credentials } : {}),
          } satisfies LighthouseV2ConfigurationUpdateInput)
        : await createLighthouseV2Configuration(
            buildLighthouseV2ConfigurationInput(
              providerType,
              credentials as LighthouseV2Credentials,
              baseUrl,
            ),
          );

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
      if (shouldTestAfterSave) {
        await runConnectionTest(result.data.id);
      }
    } catch {
      onFeedback({
        title: "Configuration not saved",
        description: "Something went wrong while saving. Please try again.",
        variant: FEEDBACK_VARIANT.ERROR,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    if (!configuration) return;

    await runConnectionTest(configuration.id);
  };

  const handleDelete = async () => {
    if (!configuration) return;

    setDeleting(true);

    try {
      const result = await deleteLighthouseV2Configuration(configuration.id);

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
    } catch {
      onFeedback({
        title: "Configuration not removed",
        description: "Something went wrong while deleting. Please try again.",
        variant: FEEDBACK_VARIANT.ERROR,
      });
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      <Card
        variant="inner"
        padding="none"
        className="h-full min-w-0 p-4 md:p-5"
      >
        <section className="flex h-full w-full min-w-0 flex-col gap-4">
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
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

          <div
            aria-hidden="true"
            className="border-border-neutral-secondary border-t"
          />

          <form
            className="flex min-h-0 w-full flex-1 flex-col gap-4"
            onSubmit={form.handleSubmit(handleSave)}
            noValidate
          >
            <div className="min-h-0 overflow-y-auto">
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
                  hasStoredCredentials={hasConfiguration}
                  provider={providerType}
                  register={form.register}
                />
              </ConfigurationSection>
            </div>

            <div className="mt-auto flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
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
        </section>
      </Card>

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
    </>
  );
}
