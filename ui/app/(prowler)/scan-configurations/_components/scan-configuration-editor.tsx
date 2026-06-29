"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRef } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  createScanConfiguration,
  updateScanConfiguration,
} from "@/actions/scan-configurations";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import {
  Button,
  Field,
  FieldError,
  FieldLabel,
  Input,
  Textarea,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { fontMono } from "@/config/fonts";
import {
  convertToYaml,
  defaultScanConfigurationYaml,
  validateScanConfigurationPayload,
} from "@/lib/yaml";
import { scanConfigurationFormSchema } from "@/types/formSchemas";
import { ProviderProps } from "@/types/providers";
import { ScanConfigurationData } from "@/types/scan-configurations";

interface ScanConfigurationEditorProps {
  open: boolean;
  onClose: (saved: boolean) => void;
  richProviders: ProviderProps[];
  existingConfigs: ScanConfigurationData[];
  config: ScanConfigurationData | null;
  schema: Record<string, unknown> | null;
}

interface ScanConfigurationFormProps {
  onClose: (saved: boolean) => void;
  richProviders: ProviderProps[];
  existingConfigs: ScanConfigurationData[];
  config: ScanConfigurationData | null;
  schema: Record<string, unknown> | null;
}

// `provider_ids` has a zod `.default([])`, so the resolver's input and output
// types differ — type the form with both so RHF and zodResolver line up.
type ScanConfigurationFormInput = z.input<typeof scanConfigurationFormSchema>;
type ScanConfigurationFormValues = z.output<typeof scanConfigurationFormSchema>;

const MAX_ERRORS_SHOWN = 10;

function ScanConfigurationForm({
  onClose,
  richProviders,
  existingConfigs,
  config,
  schema,
}: ScanConfigurationFormProps) {
  const isEdit = !!config;
  const { toast } = useToast();
  const errorPanelRef = useRef<HTMLDivElement | null>(null);

  // The form is remounted every time the modal opens (Radix unmounts the
  // dialog content on close), so deriving the defaults from `config` here is
  // enough to reset the form — no `useEffect` needed.
  const form = useForm<
    ScanConfigurationFormInput,
    unknown,
    ScanConfigurationFormValues
  >({
    resolver: zodResolver(scanConfigurationFormSchema),
    defaultValues: config
      ? {
          name: config.attributes.name,
          configuration: convertToYaml(config.attributes.configuration || ""),
          provider_ids: config.attributes.providers || [],
        }
      : { name: "", configuration: "", provider_ids: [] },
  });

  const configText = form.watch("configuration") || "";
  const selectedProviders = form.watch("provider_ids") || [];

  // Real-time validation against the server schema (ranges/enums). Kept out of
  // form state because it's derived purely from the current YAML text — skip it
  // while the field is empty so we don't flag an error before the user types.
  const yamlValidation = configText.trim()
    ? validateScanConfigurationPayload(configText, schema)
    : { isValid: true, errors: [] };

  // A provider can only be attached to one config at a time. We exclude
  // providers that are owned by *other* configs from the selector so the user
  // can't double-attach them. (AccountsSelector doesn't expose a per-option
  // disabled state, so filtering out is the cleanest contract here.)
  const ownerByProvider = new Map<string, string>();
  for (const c of existingConfigs) {
    if (config && c.id === config.id) continue;
    for (const pid of c.attributes.providers || []) {
      ownerByProvider.set(pid, c.attributes.name);
    }
  }
  const selectableProviders = richProviders.filter(
    (p) => !ownerByProvider.has(p.id),
  );
  const lockedCount = richProviders.length - selectableProviders.length;

  const onSubmit = form.handleSubmit(async (values) => {
    // zod validates name length and YAML *syntax*; richer schema violations
    // (ranges/enums) surface through `yamlValidation` and must block here too.
    if (yamlValidation.errors.length > 0) {
      toast({
        variant: "destructive",
        title: "Cannot save",
        description: `${yamlValidation.errors.length} validation ${
          yamlValidation.errors.length === 1 ? "error" : "errors"
        } in the configuration. Fix them before saving.`,
      });
      errorPanelRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
      return;
    }

    const formData = new FormData();
    formData.append("name", values.name.trim());
    formData.append("configuration", values.configuration);
    values.provider_ids.forEach((pid) => {
      formData.append("provider_ids", pid);
    });
    if (config) {
      formData.append("id", config.id);
    }

    try {
      const result = config
        ? await updateScanConfiguration(null, formData)
        : await createScanConfiguration(null, formData);

      if (result?.success) {
        toast({
          title: isEdit
            ? "Scan Configuration updated"
            : "Scan Configuration created",
          description: result.success,
        });
        onClose(true);
        return;
      }

      const errors = result?.errors || {};
      if (errors.name) form.setError("name", { message: errors.name });
      if (errors.configuration)
        form.setError("configuration", { message: errors.configuration });
      if (errors.provider_ids)
        form.setError("provider_ids", { message: errors.provider_ids });
      if (errors.general) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: errors.general,
        });
      } else if (errors.configuration || errors.name || errors.provider_ids) {
        toast({
          variant: "destructive",
          title: "Validation failed",
          description:
            errors.configuration ||
            errors.name ||
            errors.provider_ids ||
            "Please review the form.",
        });
      }
    } catch (e) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description:
          e instanceof Error ? e.message : "Unexpected error. Please retry.",
      });
    }
  });

  const isSubmitting = form.formState.isSubmitting;
  const nameError = form.formState.errors.name?.message;
  const configError = form.formState.errors.configuration?.message;
  const providersError = form.formState.errors.provider_ids?.message;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-5">
      <Field>
        <FieldLabel htmlFor="scan-configuration-name">Name</FieldLabel>
        <Input
          id="scan-configuration-name"
          placeholder="e.g. stricter-iam-aws"
          aria-invalid={!!nameError}
          {...form.register("name")}
        />
        {nameError && <FieldError>{nameError}</FieldError>}
      </Field>

      <Field>
        <FieldLabel htmlFor="scan-configuration-yaml">
          Configuration (YAML)
        </FieldLabel>
        <p className="text-default-500 text-tiny">
          Follows the structure of{" "}
          <CustomLink
            size="sm"
            href="https://github.com/prowler-cloud/prowler/blob/master/prowler/config/config.yaml"
          >
            prowler/config/config.yaml
          </CustomLink>
          . Allowed ranges and enums come from the server schema; invalid values
          are listed below in real time.
        </p>
        <Textarea
          id="scan-configuration-yaml"
          placeholder={defaultScanConfigurationYaml}
          rows={14}
          aria-invalid={!!configError || !yamlValidation.isValid}
          className={fontMono.className + " text-sm"}
          {...form.register("configuration")}
        />
        <div aria-live="polite" className="mt-1" ref={errorPanelRef}>
          {yamlValidation.errors.length === 0 && configText.trim() ? (
            <p className="text-tiny text-success">Configuration valid</p>
          ) : yamlValidation.errors.length > 0 ? (
            <div className="border-danger-200 bg-danger-50 rounded-md border p-3">
              <p className="text-tiny text-danger mb-1 font-medium">
                {yamlValidation.errors.length} validation{" "}
                {yamlValidation.errors.length === 1 ? "error" : "errors"}:
              </p>
              <ul className="text-default-700 text-tiny list-disc space-y-1 pl-5">
                {yamlValidation.errors
                  .slice(0, MAX_ERRORS_SHOWN)
                  .map((err, idx) => (
                    <li key={`${err.path}-${idx}`}>
                      <code className="text-tiny">{err.path}</code>:{" "}
                      <span>{err.message}</span>
                    </li>
                  ))}
                {yamlValidation.errors.length > MAX_ERRORS_SHOWN && (
                  <li>
                    + {yamlValidation.errors.length - MAX_ERRORS_SHOWN} more
                  </li>
                )}
              </ul>
            </div>
          ) : null}
          {configError && (
            <FieldError className="mt-1">{configError}</FieldError>
          )}
        </div>
      </Field>

      <Field>
        <FieldLabel>Attach to accounts</FieldLabel>
        <p className="text-default-500 text-tiny">
          Pick the cloud accounts that should use this configuration on their
          next scan.
          {lockedCount > 0 && (
            <>
              {" "}
              {lockedCount} {lockedCount === 1 ? "account is" : "accounts are"}{" "}
              hidden because they are already attached to another Scan
              Configuration.
            </>
          )}
        </p>
        {selectableProviders.length === 0 ? (
          <p className="text-default-500 text-tiny italic">
            {richProviders.length === 0
              ? "No providers available in this tenant."
              : "All providers are already attached to other Scan Configurations."}
          </p>
        ) : (
          <AccountsSelector
            providers={selectableProviders}
            onBatchChange={(_filterKey, values) =>
              form.setValue("provider_ids", values, { shouldValidate: true })
            }
            selectedValues={selectedProviders}
            search={{
              placeholder: "Search accounts...",
              emptyMessage: "No accounts found.",
            }}
          />
        )}
        {providersError && <FieldError>{providersError}</FieldError>}
      </Field>

      <div className="flex w-full justify-end gap-3">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => onClose(false)}
          disabled={isSubmitting}
        >
          Cancel
        </Button>
        <Button type="submit" size="lg" disabled={isSubmitting}>
          {isSubmitting ? "Saving..." : isEdit ? "Update" : "Save"}
        </Button>
      </div>
    </form>
  );
}

export function ScanConfigurationEditor({
  open,
  onClose,
  richProviders,
  existingConfigs,
  config,
  schema,
}: ScanConfigurationEditorProps) {
  const isEdit = !!config;

  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose(false);
      }}
      title={isEdit ? "Edit Scan Configuration" : "New Scan Configuration"}
      size="2xl"
    >
      <ScanConfigurationForm
        key={config?.id ?? "new"}
        onClose={onClose}
        richProviders={richProviders}
        existingConfigs={existingConfigs}
        config={config}
        schema={schema}
      />
    </Modal>
  );
}
