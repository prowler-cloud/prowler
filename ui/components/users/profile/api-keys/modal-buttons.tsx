import { CustomButton } from "@/components/ui/custom/custom-button";

interface ModalButtonsProps {
  onCancel: () => void;
  onSubmit: () => void;
  isLoading: boolean;
  isDisabled?: boolean;
  submitText?: string;
  submitColor?: "action" | "danger";
}

export const ModalButtons = ({
  onCancel,
  onSubmit,
  isLoading,
  isDisabled = false,
  submitText = "Save",
  submitColor = "action",
}: ModalButtonsProps) => {
  return (
    <div className="flex w-full justify-end gap-3 pt-4">
      <CustomButton
        ariaLabel="Cancel"
        color="transparent"
        variant="light"
        onPress={onCancel}
        isDisabled={isLoading}
      >
        Cancel
      </CustomButton>
      <CustomButton
        ariaLabel={submitText}
        color={submitColor}
        onPress={onSubmit}
        isLoading={isLoading}
        isDisabled={isDisabled || isLoading}
      >
        {submitText}
      </CustomButton>
    </div>
  );
};
