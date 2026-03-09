"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
import { FormMessage } from "@/components/ui/form";

type RadioGroupGCPViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupGCPViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupGCPViaCredentialsFormProps) => {
  return (
    <Controller
      name="gcpCredentialsType"
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
            <span className="text-default-500 text-sm">
              Using Service Account
            </span>
            <WizardRadioCard value="service-account" isInvalid={isInvalid}>
              Connect via Service Account Key
            </WizardRadioCard>
            <span className="text-default-500 text-sm">
              Using Application Default Credentials
            </span>
            <WizardRadioCard value="credentials" isInvalid={isInvalid}>
              Connect via Application Default Credentials
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
