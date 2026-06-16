"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CloudCog, Rocket } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { scanOnDemand } from "@/actions/scans";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import {
  Button,
  Field,
  FieldError,
  FieldLabel,
  Input,
} from "@/components/shadcn";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal";
import { toast, ToastAction } from "@/components/ui/toast";
import { SCAN_JOBS_TAB } from "@/types";
import type { ProviderProps } from "@/types/providers";

import { scanAliasSchema } from "./scan-alias-validation";
import { getScanJobsTab } from "./scans.utils";

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
  const searchParams = useSearchParams();
  const form = useForm<LaunchScanFormValues>({
    resolver: zodResolver(launchScanSchema),
    defaultValues: { providerId: "", scanAlias: "" },
  });

  const providerId = form.watch("providerId");
  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
  const shouldShowActiveTabAction = activeTab !== SCAN_JOBS_TAB.ACTIVE;
  const disconnectedProviderIds = providers
    .filter((provider) => provider.attributes.connection.connected !== true)
    .map((provider) => provider.id);

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
      action: shouldShowActiveTabAction ? (
        <ToastAction altText="View scan in progress" asChild>
          <Link href="/scans?tab=active">View scan</Link>
        </ToastAction>
      ) : undefined,
    });
    onClose();
    router.refresh();
  });

  const providerError = form.formState.errors.providerId?.message;
  const aliasError = form.formState.errors.scanAlias?.message;
  const rootError = form.formState.errors.root?.message;
  const isSubmitting = form.formState.isSubmitting;

  return (
    <form onSubmit={onSubmit} className="flex w-full min-w-0 flex-col gap-8">
      <div className="flex items-center gap-2">
        <CloudCog className="text-text-neutral-secondary size-4" />
        <span className="text-text-neutral-secondary text-sm">
          Select the provider you would like to scan
        </span>
      </div>

      <Field className="min-w-0">
        <FieldLabel htmlFor="launch-scan-account">Providers</FieldLabel>
        <AccountsSelector
          id="launch-scan-account"
          providers={providers}
          disabledValues={disconnectedProviderIds}
          onBatchChange={(_, values) =>
            form.setValue("providerId", values.at(-1) ?? "", {
              shouldValidate: true,
            })
          }
          selectedValues={providerId ? [providerId] : []}
          closeOnSelect
        />
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

      <DialogFooter className="w-full min-w-0 gap-4">
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={onClose}
          className="w-full sm:w-40"
        >
          Cancel
        </Button>
        <Button
          type="submit"
          size="lg"
          disabled={isSubmitting || !providers.length}
          className="w-full sm:w-40"
        >
          <Rocket className="size-4" />
          {isSubmitting ? "Launching..." : "Launch Scan"}
        </Button>
      </DialogFooter>
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
