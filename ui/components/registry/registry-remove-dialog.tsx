import { type RefObject, useRef } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal/modal";

interface RegistryRemoveDialogProps {
  artifactName?: string;
  isPending: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
}

export function RegistryRemoveDialog({
  artifactName,
  isPending,
  onConfirm,
  onOpenChange,
  open,
  returnFocusRef,
}: RegistryRemoveDialogProps) {
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  return (
    <Modal
      description={`Remove ${artifactName ?? "this artifact"} from My artifacts.`}
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
      <div className="flex flex-wrap justify-end gap-2">
        <Button
          disabled={isPending}
          onClick={() => onOpenChange(false)}
          ref={cancelButtonRef}
          type="button"
          variant="outline"
        >
          Cancel
        </Button>
        <Button
          disabled={isPending}
          onClick={onConfirm}
          type="button"
          variant="destructive"
        >
          {isPending ? "Removing artifact" : "Confirm Remove"}
        </Button>
      </div>
    </Modal>
  );
}
