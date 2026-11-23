import { type RefObject, useEffect, useRef } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal/modal";
import {
  REGISTRY_ARTIFACT_REMOVAL,
  type RegistryRemoveDialogError,
} from "@/types/registry";

interface RegistryRemoveDialogProps {
  /** The artifact's display name. */
  artifactLabel?: string;
  error?: RegistryRemoveDialogError;
  isPending: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
  onViewProviders: () => void;
  open: boolean;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
}

export function RegistryRemoveDialog({
  artifactLabel = "this artifact",
  error,
  isPending,
  onConfirm,
  onOpenChange,
  onViewProviders,
  open,
  returnFocusRef,
}: RegistryRemoveDialogProps) {
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const isInUse = error?.status === REGISTRY_ARTIFACT_REMOVAL.IN_USE;
  // Busy keeps Remove: waiting is the remedy, not deleting providers.
  const isBusy = error?.status === REGISTRY_ARTIFACT_REMOVAL.BUSY;

  // Disabling the submit button can lose focus; restore it inside the dialog
  // when a failure re-enables the actions or replaces them with recovery actions.
  useEffect(() => {
    if (open && error) cancelButtonRef.current?.focus();
  }, [error, open]);

  return (
    <Modal
      description={
        isInUse
          ? "One or more providers use it. Delete those providers first, then try again."
          : "Future scans stop using it. Findings from past scans stay."
      }
      onOpenAutoFocus={(event) => {
        event.preventDefault();
        cancelButtonRef.current?.focus();
      }}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        returnFocusRef.current?.focus();
      }}
      onOpenChange={onOpenChange}
      open={open}
      size="sm"
      title={
        isInUse ? `${artifactLabel} is in use` : `Remove ${artifactLabel}?`
      }
    >
      {/* Title and description change in place; this announces the outcome. */}
      {isInUse && (
        <p className="sr-only" role="alert">
          {`${artifactLabel} is in use. Delete the providers that use it first.`}
        </p>
      )}
      {error && !isInUse && (
        <Alert variant="error">
          {isBusy && <AlertTitle>A scan is using this artifact</AlertTitle>}
          <AlertDescription>
            {isBusy
              ? "A scan is running the checks this artifact adds. It clears by itself when the scan finishes, so try again shortly."
              : error.message}
          </AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button
          disabled={isPending}
          onClick={() => onOpenChange(false)}
          ref={cancelButtonRef}
          type="button"
          variant="outline"
        >
          {isInUse ? "Close" : "Cancel"}
        </Button>
        {isInUse ? (
          <Button onClick={onViewProviders} type="button">
            View providers
          </Button>
        ) : (
          <Button
            disabled={isPending}
            onClick={onConfirm}
            type="button"
            variant="destructive"
          >
            {isPending ? "Removing…" : "Remove"}
          </Button>
        )}
      </div>
    </Modal>
  );
}
