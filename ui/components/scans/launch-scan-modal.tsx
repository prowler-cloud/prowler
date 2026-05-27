"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CloudCog, Rocket } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { scanOnDemand } from "@/actions/scans";
import {
  Field,
  FieldError,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import type { ProviderProps } from "@/types/providers";

import { scanAliasSchema } from "./scan-alias-validation";

const launchScanSchema = z.object({
  providerId: z.string().min(1, "Select a provider to launch a scan."),
  scanAlias: scanAliasSchema.optional(),
});

type LaunchScanFormValues = z.infer<typeof launchScanSchema>;

interface LaunchScanModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providers: ProviderProps[];
}

interface LaunchScanFormProps {
  providers: ProviderProps[];
  onClose: () => void;
}

function LaunchScanForm({ providers, onClose }: LaunchScanFormProps) {
  const router = useRouter();
  const form = useForm<LaunchScanFormValues>({
    resolver: zodResolver(launchScanSchema),
    defaultValues: { providerId: "", scanAlias: "" },
  });

  const providerId = form.watch("providerId");

  const onSubmit = form.handleSubmit(async ({ providerId, scanAlias }) => {
    const formData = new FormData();
    formData.set("providerId", providerId);
    const trimmedAlias = scanAlias?.trim();
    if (trimmedAlias) {
      formData.set("scanName", trimmedAlias);
    }

    const result = await scanOnDemand(formData);

    if (result?.error) {
      form.setError("root", { message: String(result.error) });
      return;
    }

    if (result?.errors && result.errors.length > 0) {
      form.setError("root", {
        message: String(result.errors[0]?.detail ?? "Failed to launch scan."),
      });
      return;
    }

    toast({
      title: "Scan launched",
      description: "The scan was launched successfully.",
    });
    onClose();
    router.refresh();
  });

  const providerError = form.formState.errors.providerId?.message;
  const aliasError = form.formState.errors.scanAlias?.message;
  const rootError = form.formState.errors.root?.message;
  const isSubmitting = form.formState.isSubmitting;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-8">
      <div className="flex items-center gap-2">
        <CloudCog className="text-text-neutral-secondary size-4" />
        <span className="text-text-neutral-secondary text-sm">
          Select the provider you would like to scan
        </span>
      </div>

      <Field>
        <FieldLabel htmlFor="launch-scan-account">Providers</FieldLabel>
        <Select
          value={providerId}
          onValueChange={(value) =>
            form.setValue("providerId", value, { shouldValidate: true })
          }
        >
          <SelectTrigger id="launch-scan-account" aria-label="Providers">
            <SelectValue placeholder="Select a provider" />
          </SelectTrigger>
          <SelectContent>
            {providers.map((provider) => {
              const alias = provider.attributes.alias;
              const uid = provider.attributes.uid;
              const showUid = Boolean(alias) && alias !== uid;
              return (
                <SelectItem
                  key={provider.id}
                  value={provider.id}
                  disabled={provider.attributes.connection.connected !== true}
                >
                  <span className="truncate">{alias || uid}</span>
                  {showUid && (
                    <span className="text-text-neutral-secondary text-xs">
                      {uid}
                    </span>
                  )}
                </SelectItem>
              );
            })}
          </SelectContent>
        </Select>
        {providerError && <FieldError>{providerError}</FieldError>}
      </Field>

      <Field>
        <FieldLabel htmlFor="launch-scan-alias">Alias (optional)</FieldLabel>
        <Input
          id="launch-scan-alias"
          aria-label="Alias"
          {...form.register("scanAlias")}
        />
        {aliasError && <FieldError>{aliasError}</FieldError>}
      </Field>

      {rootError && <FieldError>{rootError}</FieldError>}

      <FormButtons
        onCancel={onClose}
        submitText={isSubmitting ? "Launching..." : "Launch Scan"}
        loadingText="Launching..."
        isDisabled={isSubmitting || !providers.length}
        rightIcon={<Rocket className="size-4" />}
      />
    </form>
  );
}

export function LaunchScanModal({
  open,
  onOpenChange,
  providers,
}: LaunchScanModalProps) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Launch A Scan"
      size="xl"
      className="gap-8"
    >
      <LaunchScanForm
        providers={providers}
        onClose={() => onOpenChange(false)}
      />
    </Modal>
  );
}
