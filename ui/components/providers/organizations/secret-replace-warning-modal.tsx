"use client";

import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";

interface SecretReplaceWarningModalProps {
  warning: { providerCount: number } | null;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Shown when organization setup would overwrite an existing credential, which
 * re-authenticates every provider already onboarded under the organization.
 */
export function SecretReplaceWarningModal({
  warning,
  onConfirm,
  onCancel,
}: SecretReplaceWarningModalProps) {
  const providerCount = warning?.providerCount ?? 0;

  return (
    <Modal
      open={warning !== null}
      onOpenChange={(open) => {
        if (!open) onCancel();
      }}
      title="Replace existing credentials?"
      description={
        providerCount > 0
          ? `This organization already has credentials. Replacing them re-authenticates its ${providerCount} ${
              providerCount === 1 ? "provider" : "providers"
            }.`
          : "This organization already has credentials. They will be replaced with the ones you just entered."
      }
    >
      <div className="flex w-full justify-end gap-4">
        <Button type="button" variant="ghost" size="lg" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          type="button"
          variant="destructive"
          size="lg"
          onClick={onConfirm}
        >
          Replace credentials
        </Button>
      </div>
    </Modal>
  );
}
