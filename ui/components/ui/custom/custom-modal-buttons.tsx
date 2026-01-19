import { Loader2 } from "lucide-react";
import { ReactNode } from "react";

import { Button } from "@/components/shadcn";

interface ModalButtonsProps {
  onCancel: () => void;
  onSubmit: () => void;
  isLoading: boolean;
  isDisabled?: boolean;
  submitText?: string;
  submitColor?: "action" | "danger";
  submitIcon?: ReactNode;
}

export const ModalButtons = ({
  onCancel,
  onSubmit,
  isLoading,
  isDisabled = false,
  submitText = "Save",
  submitColor = "action",
  submitIcon,
}: ModalButtonsProps) => {
  const submitVariant = submitColor === "danger" ? "destructive" : "default";

  return (
    <div className="flex w-full justify-end gap-4">
      <Button
        size="lg"
        variant="ghost"
        type="button"
        onClick={onCancel}
        disabled={isLoading}
      >
        Cancel
      </Button>
      <Button
        size="lg"
        variant={submitVariant}
        onClick={onSubmit}
        disabled={isDisabled || isLoading}
      >
        {isLoading ? (
          <Loader2 className="animate-spin" />
        ) : (
          submitIcon && submitIcon
        )}
        {isLoading ? "Loading" : submitText}
      </Button>
    </div>
  );
};
