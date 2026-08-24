import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal/modal";

interface RegistryRemoveDialogProps {
  artifactName?: string;
  isPending: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
}

export function RegistryRemoveDialog({
  artifactName,
  isPending,
  onConfirm,
  onOpenChange,
  open,
}: RegistryRemoveDialogProps) {
  return (
    <Modal
      description={`Remove ${artifactName ?? "this artifact"} from My artifacts.`}
      onOpenChange={onOpenChange}
      open={open}
      size="sm"
      title="Remove artifact"
    >
      <div className="flex flex-wrap justify-end gap-2">
        <Button
          disabled={isPending}
          onClick={() => onOpenChange(false)}
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
