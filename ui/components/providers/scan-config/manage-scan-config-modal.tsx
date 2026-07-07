"use client";

import { useState } from "react";

import { setScanConfigurationProviders } from "@/actions/scan-configurations";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { Modal } from "@/components/shadcn/modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { DOCS_URLS } from "@/lib/external-urls";
import { ScanConfigurationData } from "@/types/scan-configurations";

// Sentinel for the "Default" option: detaches the provider so its scans fall
// back to Prowler's built-in SDK defaults. Select values must be non-empty
// strings, so we can't use "".
const DEFAULT_VALUE = "__default__";

interface ManageScanConfigModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providerId: string;
  providerLabel: string;
  scanConfigs: ScanConfigurationData[];
  /** The config this provider is currently attached to, if any. */
  currentConfigId: string | null;
  /** Called after a successful associate/disassociate so the parent can refresh. */
  onSaved: () => void;
}

type ManageScanConfigFormProps = Omit<ManageScanConfigModalProps, "open">;

export function ManageScanConfigModal({
  open,
  onOpenChange,
  ...formProps
}: ManageScanConfigModalProps) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Scan Configuration"
      size="md"
    >
      {/* Only mount the form while the modal is open so a fresh instance is
          created on every reopen — its selection always initializes from the
          provider's current config, never from a stale, cancelled selection.
          The key resets it again if the attached config changes mid-open. */}
      {open && (
        <ManageScanConfigForm
          key={`${formProps.providerId}:${formProps.currentConfigId ?? DEFAULT_VALUE}`}
          onOpenChange={onOpenChange}
          {...formProps}
        />
      )}
    </Modal>
  );
}

function ManageScanConfigForm({
  onOpenChange,
  providerId,
  providerLabel,
  scanConfigs,
  currentConfigId,
  onSaved,
}: ManageScanConfigFormProps) {
  const { toast } = useToast();
  const [selected, setSelected] = useState<string>(
    currentConfigId ?? DEFAULT_VALUE,
  );
  const [isSaving, setIsSaving] = useState(false);

  const handleSave = async () => {
    // No change — nothing to do.
    if (selected === (currentConfigId ?? DEFAULT_VALUE)) {
      onOpenChange(false);
      return;
    }

    const reportError = (description: string) => {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description,
      });
    };

    setIsSaving(true);
    try {
      let result;
      if (selected === DEFAULT_VALUE) {
        // Detach: drop this provider from its current config.
        if (!currentConfigId) {
          onOpenChange(false);
          return;
        }
        const current = scanConfigs.find((c) => c.id === currentConfigId);
        // Bail if we don't have the current config loaded: sending a full
        // provider_ids replacement off a synthetic empty list would clear every
        // other provider attached to this configuration.
        if (!current) {
          reportError(
            "This scan configuration is no longer available. Refresh and try again.",
          );
          return;
        }
        const next = current.attributes.providers.filter(
          (id) => id !== providerId,
        );
        result = await setScanConfigurationProviders(currentConfigId, next);
      } else {
        // Attach: add this provider to the chosen config. The backend moves it
        // off any other config automatically (one config per provider).
        const target = scanConfigs.find((c) => c.id === selected);
        // Same guard as the detach path: never replace provider_ids based on a
        // config we don't actually have.
        if (!target) {
          reportError(
            "This scan configuration is no longer available. Refresh and try again.",
          );
          return;
        }
        const next = Array.from(
          new Set([...target.attributes.providers, providerId]),
        );
        result = await setScanConfigurationProviders(selected, next);
      }

      if (result?.success) {
        toast({
          title: "Scan Configuration updated",
          description: result.success,
        });
        onSaved();
        onOpenChange(false);
      } else {
        reportError(
          result?.errors?.general ||
            result?.errors?.provider_ids ||
            "Failed to update the Scan Configuration. Please try again.",
        );
      }
    } catch {
      // An invocation-level failure (transport/framework) rejects instead of
      // returning an error object — surface it instead of failing silently.
      reportError("Failed to update the Scan Configuration. Please try again.");
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-text-neutral-tertiary text-xs">
        Choose the scan configuration to apply to{" "}
        <strong>{providerLabel}</strong> on its next scan, or leave default. To
        create or edit configurations, go to{" "}
        <CustomLink size="xs" href="/scans/config" target="_self">
          Scan Config
        </CustomLink>
        .
      </p>

      {/* Always show the dropdown with Default — even with no custom configs,
          the provider can fall back to Prowler's SDK defaults. */}
      <div className="flex flex-col gap-1">
        <Select value={selected} onValueChange={setSelected}>
          <SelectTrigger aria-label="Scan configuration">
            <SelectValue placeholder="Default" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={DEFAULT_VALUE}>Default</SelectItem>
            {scanConfigs.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.attributes.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-text-neutral-tertiary text-xs">
          <strong>Default</strong>
          {
            " uses Prowler's scan configuration baseline. Read more about it in the "
          }
          <CustomLink size="xs" href={DOCS_URLS.SCAN_CONFIGURATION}>
            documentation
          </CustomLink>
          .
        </p>
      </div>

      <div className="flex w-full justify-end gap-3">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => onOpenChange(false)}
          disabled={isSaving}
        >
          Cancel
        </Button>
        <Button
          type="button"
          size="lg"
          onClick={handleSave}
          disabled={isSaving}
        >
          {isSaving ? "Saving..." : "Save"}
        </Button>
      </div>
    </div>
  );
}
