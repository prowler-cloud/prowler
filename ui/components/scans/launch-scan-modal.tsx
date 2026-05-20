"use client";

import { Cloud, Rocket } from "lucide-react";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useState } from "react";

import { scanOnDemand } from "@/actions/scans";
import {
  Field,
  FieldError,
  FieldLabel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Textarea,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { EntityInfo } from "@/components/ui/entities";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import type { ProviderType, ScanProviderInfo } from "@/types";

interface LaunchScanModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providers: ScanProviderInfo[];
}

export function LaunchScanModal({
  open,
  onOpenChange,
  providers,
}: LaunchScanModalProps) {
  const router = useRouter();
  const [providerId, setProviderId] = useState("");
  const [scanNote, setScanNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const selectedProvider = providers.find(
    (provider) => provider.providerId === providerId,
  );

  const closeModal = () => {
    setProviderId("");
    setScanNote("");
    setError(null);
    onOpenChange(false);
  };

  const launchScan = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!providerId) {
      setError("Select a cloud account to launch a scan.");
      return;
    }

    setSubmitting(true);
    setError(null);

    const formData = new FormData();
    formData.set("providerId", providerId);
    if (scanNote.trim()) {
      formData.set("scanNote", scanNote.trim());
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
    >
      <form onSubmit={launchScan} className="flex flex-col gap-5">
        <div className="flex items-center gap-2">
          <Cloud className="text-text-neutral-secondary size-4" />
          <span className="text-text-neutral-secondary text-sm">
            Select a Cloud Account you would like to scan
          </span>
        </div>

        <Field>
          <FieldLabel htmlFor="launch-scan-account">Cloud Account</FieldLabel>
          <Select value={providerId} onValueChange={setProviderId}>
            <SelectTrigger id="launch-scan-account" aria-label="Cloud Account">
              <SelectValue placeholder="Select one">
                {selectedProvider ? (
                  <EntityInfo
                    cloudProvider={
                      selectedProvider.providerType as ProviderType
                    }
                    entityAlias={selectedProvider.alias}
                    entityId={selectedProvider.uid}
                    showCopyAction={false}
                  />
                ) : (
                  "Select one"
                )}
              </SelectValue>
            </SelectTrigger>
            <SelectContent width="wide" className="z-[60]">
              {providers.map((provider) => (
                <SelectItem
                  key={provider.providerId}
                  value={provider.providerId}
                >
                  <EntityInfo
                    cloudProvider={provider.providerType as ProviderType}
                    entityAlias={provider.alias}
                    entityId={provider.uid}
                    showCopyAction={false}
                  />
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>

        <Field>
          <FieldLabel htmlFor="launch-scan-note">
            Scan Note (optional)
          </FieldLabel>
          <Textarea
            id="launch-scan-note"
            aria-label="Scan Note"
            value={scanNote}
            onChange={(event) => setScanNote(event.target.value)}
            textareaSize="sm"
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
