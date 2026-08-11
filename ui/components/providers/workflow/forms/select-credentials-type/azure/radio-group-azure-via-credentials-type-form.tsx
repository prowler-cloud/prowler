"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { FormMessage } from "@/components/shadcn/form";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";

type RadioGroupAzureViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

// The via values (`app_client_secret` / `app_certificate`) mirror M365 on
// purpose: both providers authenticate against an Entra ID App Registration
// and reuse the same wizard state machine + per-method docs anchors.
export const RadioGroupAzureViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupAzureViaCredentialsFormProps) => {
  return (
    <Controller
      name="azureCredentialsType"
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
            <span className="text-text-neutral-tertiary text-sm">
              Select Authentication Method
            </span>
            <WizardRadioCard value="app_certificate" isInvalid={isInvalid}>
              Certificate Authentication (Recommended)
            </WizardRadioCard>
            <WizardRadioCard value="app_client_secret" isInvalid={isInvalid}>
              Service Principal with Client Secret
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
