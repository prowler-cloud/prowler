"use client";

import { Dispatch, SetStateAction } from "react";
import { useFormStatus } from "react-dom";

import { SaveIcon } from "@/components/icons";

import { CustomButton } from "../custom";

interface FormCancelButtonProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  children?: React.ReactNode;
}

interface FormSubmitButtonProps {
  children?: React.ReactNode;
  loadingText?: string;
}

interface FormButtonsProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  submitText?: string;
  cancelText?: string;
  loadingText?: string;
}

export const FormCancelButton = ({
  setIsOpen,
  children = "Cancel",
}: FormCancelButtonProps) => {
  return (
    <CustomButton
      type="button"
      ariaLabel="Cancel"
      className="w-full bg-transparent"
      variant="faded"
      size="lg"
      onPress={() => setIsOpen(false)}
    >
      <span>{children}</span>
    </CustomButton>
  );
};

export const FormSubmitButton = ({
  children = "Save",
  loadingText = "Loading",
}: FormSubmitButtonProps) => {
  const { pending } = useFormStatus();

  return (
    <CustomButton
      type="submit"
      ariaLabel="Save"
      className="w-full"
      variant="solid"
      color="action"
      size="lg"
      isLoading={pending}
      startContent={!pending && <SaveIcon size={24} />}
    >
      {pending ? <>{loadingText}</> : <span>{children}</span>}
    </CustomButton>
  );
};

export const FormButtons = ({
  setIsOpen,
  submitText = "Save",
  cancelText = "Cancel",
  loadingText = "Loading",
}: FormButtonsProps) => {
  return (
    <div className="flex w-full justify-center space-x-6">
      <FormCancelButton setIsOpen={setIsOpen}>{cancelText}</FormCancelButton>

      <FormSubmitButton loadingText={loadingText}>
        {submitText}
      </FormSubmitButton>
    </div>
  );
};
