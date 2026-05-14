"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
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
          <RadioGroup
            name={field.name}
            value={field.value || ""}
            onValueChange={(value: string) => {
              field.onChange(value);
              onChange?.(value);
            }}
          >
            <span className="text-default-500 text-sm">Using IAM Role</span>
            <WizardRadioCard value="role" isInvalid={isInvalid}>
              Connect assuming IAM Role
            </WizardRadioCard>
            <span className="text-default-500 text-sm">Using Credentials</span>
            <WizardRadioCard value="credentials" isInvalid={isInvalid}>
              Connect via Credentials
            </WizardRadioCard>
          </RadioGroup>
          {errorMessage && (
            <FormMessage className="text-text-error-primary">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
