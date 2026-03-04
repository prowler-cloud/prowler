"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { FormMessage } from "@/components/ui/form";

type RadioGroupAWSViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupAWSViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupAWSViaCredentialsFormProps) => {
  return (
    <Controller
      name="awsCredentialsType"
      control={control}
      render={({ field }) => (
        <>
          <div className="flex flex-col gap-4">
            <span className="text-default-500 text-sm">Using IAM Role</span>
            <WizardRadioCard
              name={field.name}
              value="role"
              checked={(field.value || "") === "role"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              Connect assuming IAM Role
            </WizardRadioCard>
            <span className="text-default-500 text-sm">Using Credentials</span>
            <WizardRadioCard
              name={field.name}
              value="credentials"
              checked={(field.value || "") === "credentials"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              Connect via Credentials
            </WizardRadioCard>
          </div>
          {errorMessage && (
            <FormMessage className="text-text-error">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
