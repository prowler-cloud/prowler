import { ReactNode } from "react";

import { CustomButton } from "@/components/ui/custom/custom-button";

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
  return (
    <div className="flex w-full justify-center gap-6">
      <CustomButton
        size="lg"
        radius="lg"
        variant="faded"
        type="button"
        ariaLabel="Cancel"
        className="w-full bg-transparent"
        onPress={onCancel}
        isDisabled={isLoading}
      >
        Cancel
      </CustomButton>
      <CustomButton
        size="lg"
        radius="lg"
        className="w-full"
        ariaLabel={submitText}
        color={submitColor}
        onPress={onSubmit}
        isLoading={isLoading}
        isDisabled={isDisabled || isLoading}
        startContent={submitIcon}
      >
        {submitText}
      </CustomButton>
    </div>
  );
};
