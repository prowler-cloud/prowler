"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
import { FormMessage } from "@/components/ui/form";

type RadioGroupM365ViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupM365ViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupM365ViaCredentialsFormProps) => {
  return (
    <Controller
      name="m365CredentialsType"
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
              Select Authentication Method
            </span>
            <WizardRadioCard value="app_client_secret" isInvalid={isInvalid}>
              App Client Secret Credentials
            </WizardRadioCard>
            <WizardRadioCard value="app_certificate" isInvalid={isInvalid}>
              App Certificate Credentials
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
