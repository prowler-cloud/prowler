"use client";

import { CloudCog, Rocket } from "lucide-react";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useState } from "react";

import { scanOnDemand } from "@/actions/scans";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { Field, FieldError, FieldLabel, Input } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import type { ProviderProps } from "@/types/providers";

interface LaunchScanModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providers: ProviderProps[];
}

export function LaunchScanModal({
  open,
  onOpenChange,
  providers,
}: LaunchScanModalProps) {
  const router = useRouter();
  const [providerId, setProviderId] = useState("");
  const [scanAlias, setScanAlias] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const closeModal = () => {
    setProviderId("");
    setScanAlias("");
    setError(null);
    onOpenChange(false);
  };

  const launchScan = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!providerId) {
      setError("Select a provider to launch a scan.");
      return;
    }

    setSubmitting(true);
    setError(null);

    const formData = new FormData();
    formData.set("providerId", providerId);
    if (scanAlias.trim()) {
      formData.set("scanName", scanAlias.trim());
    }

    const result = await scanOnDemand(formData);
    setSubmitting(false);

    if (result?.error) {
      setError(String(result.error));
      return;
    }

    toast({
      title: "Scan launched",
      description: "The scan was launched successfully.",
    });
    closeModal();
    router.refresh();
  };

  return (
    <Modal
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) closeModal();
        else onOpenChange(true);
      }}
      title="Launch A Scan"
      size="xl"
      className="gap-8"
    >
      <form onSubmit={launchScan} className="flex flex-col gap-8">
        <div className="flex items-center gap-2">
          <CloudCog className="text-text-neutral-secondary size-4" />
          <span className="text-text-neutral-secondary text-sm">
            Select the provider you would like to scan
          </span>
        </div>

        <Field>
          <FieldLabel htmlFor="launch-scan-account">Providers</FieldLabel>
          <AccountsSelector
            id="launch-scan-account"
            providers={providers}
            onBatchChange={(_, values) => setProviderId(values.at(-1) ?? "")}
            selectedValues={providerId ? [providerId] : []}
          />
        </Field>

        <Field>
          <FieldLabel htmlFor="launch-scan-alias">Alias (optional)</FieldLabel>
          <Input
            id="launch-scan-alias"
            aria-label="Alias"
            value={scanAlias}
            onChange={(event) => setScanAlias(event.target.value)}
          />
        </Field>

        {error && <FieldError>{error}</FieldError>}

        <FormButtons
          onCancel={closeModal}
          submitText={submitting ? "Launching..." : "Launch Scan"}
          loadingText="Launching..."
          isDisabled={submitting || !providers.length}
          rightIcon={<Rocket className="size-4" />}
        />
      </form>
    </Modal>
  );
}
