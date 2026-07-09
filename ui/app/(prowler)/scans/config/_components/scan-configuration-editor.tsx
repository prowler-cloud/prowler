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
import { useToast } from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { Modal } from "@/components/shadcn/modal";
import { DOCS_URLS } from "@/lib/external-urls";
import {
  convertToYaml,
  defaultScanConfigurationYaml,
  validateYaml,
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
}

interface ScanConfigurationFormProps {
  onClose: (saved: boolean) => void;
  richProviders: ProviderProps[];
  existingConfigs: ScanConfigurationData[];
  config: ScanConfigurationData | null;
}

// `provider_ids` has a zod `.default([])`, so the resolver's input and output
// types differ — type the form with both so RHF and zodResolver line up.
type ScanConfigurationFormInput = z.input<typeof scanConfigurationFormSchema>;
type ScanConfigurationFormValues = z.output<typeof scanConfigurationFormSchema>;

function ScanConfigurationForm({
  onClose,
  richProviders,
  existingConfigs,
  config,
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

  // Mirror the Mutelist editor: the client validates YAML *syntax* live (that it
  // parses to a mapping); the API validates the configuration values
  // (ranges/enums) on save and returns them inline. Skip while empty so we don't
  // flag an error before the user types.
  const yamlSyntax = configText.trim()
    ? validateYaml(configText)
    : { isValid: true as const };

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
    // Block on a YAML syntax error (the inline message already explains it); the
    // API validates the values on save and returns any errors inline.
    if (!yamlSyntax.isValid) {
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

      // Field-level errors render inline next to each input; only a general
      // error (no field to anchor it to) falls back to a toast.
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
        <ul className="text-text-neutral-tertiary mb-1 list-disc pl-5 text-xs">
          <li>
            Follows the structure of{" "}
            <code className="bg-bg-neutral-tertiary text-text-neutral-secondary rounded px-1 py-0.5 font-mono">
              prowler/config/config.yaml
            </code>
            ; include only the keys you want to override. Learn more{" "}
            <CustomLink size="xs" href={DOCS_URLS.SCAN_CONFIGURATION}>
              here
            </CustomLink>
            .
          </li>
          <li>The configuration is validated on save.</li>
        </ul>
        <Textarea
          id="scan-configuration-yaml"
          placeholder={defaultScanConfigurationYaml}
          rows={14}
          aria-invalid={!!configError || !yamlSyntax.isValid}
          font="mono"
          {...form.register("configuration", {
            // A server-side validation error becomes stale the moment the user
            // edits the YAML — clear it so it can't linger next to the live
            // client-side syntax check.
            onChange: () => form.clearErrors("configuration"),
          })}
        />
        <div
          aria-live="polite"
          className="mt-1 flex flex-col gap-1"
          ref={errorPanelRef}
        >
          {!yamlSyntax.isValid ? (
            <FieldError>{`Invalid YAML format: ${yamlSyntax.error}`}</FieldError>
          ) : configText.trim() && !configError ? (
            <p className="text-text-success-primary text-xs">
              Valid YAML format
            </p>
          ) : null}
          {configError && <FieldError multiline>{configError}</FieldError>}
        </div>
      </Field>

      <Field>
        <FieldLabel>Attach to providers (optional)</FieldLabel>
        <p className="text-text-neutral-tertiary text-xs">
          Pick the providers that should use this configuration on their next
          scan. You can save it without any and attach providers later — it just
          won&apos;t apply to a scan until one is attached.
          {lockedCount > 0 && (
            <>
              {" "}
              {lockedCount}{" "}
              {lockedCount === 1 ? "provider is" : "providers are"} hidden
              because they are already attached to another Scan Configuration.
            </>
          )}
        </p>
        {selectableProviders.length === 0 ? (
          <p className="text-text-neutral-tertiary text-xs italic">
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
            // Here an empty selection means "no providers attached" (the field
            // is optional), not the filter default of "all providers". Override
            // the filter-oriented labels so the control reads correctly.
            placeholder="No providers selected"
            emptySelectionLabel="No providers selected"
            clearSelectionLabel="Clear selection"
            search={{
              placeholder: "Search providers...",
              emptyMessage: "No providers found.",
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
        <Button
          type="submit"
          size="lg"
          disabled={isSubmitting || !yamlSyntax.isValid}
        >
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
      scrollable
    >
      <ScanConfigurationForm
        key={config?.id ?? "new"}
        onClose={onClose}
        richProviders={richProviders}
        existingConfigs={existingConfigs}
        config={config}
      />
    </Modal>
  );
}
