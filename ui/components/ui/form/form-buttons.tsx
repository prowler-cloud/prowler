"use client";

import { Dispatch, SetStateAction } from "react";
import { useFormStatus } from "react-dom";

import { SaveIcon } from "@/components/icons";

import { CustomButton } from "../custom";

interface FormCancelButtonProps {
  setIsOpen?: Dispatch<SetStateAction<boolean>>;
  onCancel?: () => void;
  children?: React.ReactNode;
  leftIcon?: React.ReactNode;
}

interface FormSubmitButtonProps {
  children?: React.ReactNode;
  loadingText?: string;
  isDisabled?: boolean;
  rightIcon?: React.ReactNode;
  color?: SubmitColorsType;
}

interface FormButtonsProps {
  setIsOpen?: Dispatch<SetStateAction<boolean>>;
  onCancel?: () => void;
  submitText?: string;
  cancelText?: string;
  loadingText?: string;
  isDisabled?: boolean;
  rightIcon?: React.ReactNode;
  leftIcon?: React.ReactNode;
  submitColor?: SubmitColorsType;
}

export const SubmitColors = {
  action: "action",
  danger: "danger",
} as const;

export type SubmitColorsType = (typeof SubmitColors)[keyof typeof SubmitColors];

const FormCancelButton = ({
  setIsOpen,
  onCancel,
  children = "Cancel",
  leftIcon,
}: FormCancelButtonProps) => {
  const handleCancel = () => {
    if (onCancel) {
      onCancel();
    } else if (setIsOpen) {
      setIsOpen(false);
    }
  };

  return (
    <CustomButton
      type="button"
      ariaLabel="Cancel"
      className="w-full bg-transparent"
      variant="faded"
      size="lg"
      radius="lg"
      onPress={handleCancel}
      startContent={leftIcon}
    >
      <span>{children}</span>
    </CustomButton>
  );
};

const FormSubmitButton = ({
  children = "Save",
  loadingText = "Loading",
  isDisabled = false,
  color = "action",
  rightIcon,
}: FormSubmitButtonProps) => {
  const { pending } = useFormStatus();

  return (
    <CustomButton
      type="submit"
      ariaLabel="Save"
      className="w-full"
      variant="solid"
      color={color}
      size="lg"
      radius="lg"
      isLoading={pending}
      isDisabled={isDisabled}
      startContent={!pending && rightIcon}
    >
      {pending ? <>{loadingText}</> : <span>{children}</span>}
    </CustomButton>
  );
};

export const FormButtons = ({
  setIsOpen,
  submitColor,
  onCancel,
  submitText = "Save",
  cancelText = "Cancel",
  loadingText = "Loading",
  isDisabled = false,
  rightIcon = <SaveIcon size={24} />,
  leftIcon,
}: FormButtonsProps) => {
  return (
    <div className="flex w-full justify-center gap-6">
      <FormCancelButton
        setIsOpen={setIsOpen}
        onCancel={onCancel}
        leftIcon={leftIcon}
      >
        {cancelText}
      </FormCancelButton>

      <FormSubmitButton
        loadingText={loadingText}
        isDisabled={isDisabled}
        rightIcon={rightIcon}
        color={submitColor}
      >
        {submitText}
      </FormSubmitButton>
    </div>
  );
};
