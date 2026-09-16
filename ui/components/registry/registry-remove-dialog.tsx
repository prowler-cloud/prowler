import { type RefObject, useEffect, useRef } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal/modal";
import {
  REGISTRY_ARTIFACT_REMOVAL,
  type RegistryRemoveDialogError,
} from "@/types/registry";

interface RegistryRemoveDialogProps {
  artifactName?: string;
  error?: RegistryRemoveDialogError;
  isPending: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
  onViewProviders: () => void;
  open: boolean;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
}

export function RegistryRemoveDialog({
  artifactName,
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

  // Disabling the submit button can lose focus; restore it inside the dialog
  // when a failure re-enables the actions or replaces them with recovery actions.
  useEffect(() => {
    if (open && error) cancelButtonRef.current?.focus();
  }, [error, open]);

  return (
    <Modal
      description={`Remove ${artifactName ?? "this artifact"} from My artifacts. Artifacts used by providers cannot be removed.`}
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
      title="Remove artifact"
    >
      {error && (
        <Alert variant="error">
          {isInUse && <AlertTitle>Artifact in use</AlertTitle>}
          <AlertDescription>
            {error.status === REGISTRY_ARTIFACT_REMOVAL.IN_USE
              ? "This artifact cannot be removed because one or more providers use it. Review the associated providers before trying again."
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
            {isPending ? "Removing artifact" : "Confirm Remove"}
          </Button>
        )}
      </div>
    </Modal>
  );
}
