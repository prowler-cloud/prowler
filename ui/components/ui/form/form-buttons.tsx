"use client";

import { Loader2 } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { useFormStatus } from "react-dom";

import { SaveIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";

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
    <Button type="button" variant="ghost" size="lg" onClick={handleCancel}>
      {leftIcon}
      {children}
    </Button>
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
  const submitVariant = color === "danger" ? "destructive" : "default";

  return (
    <Button
      type="submit"
      variant={submitVariant}
      size="lg"
      disabled={isDisabled || pending}
    >
      {pending ? <Loader2 className="animate-spin" /> : rightIcon}
      {pending ? loadingText : children}
    </Button>
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
    <div className="flex w-full justify-end gap-4">
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
