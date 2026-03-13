"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
import { FormMessage } from "@/components/ui/form";

type RadioGroupCloudflareViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupCloudflareViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupCloudflareViaCredentialsFormProps) => {
  return (
    <Controller
      name="cloudflareCredentialsType"
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
            <WizardRadioCard value="api_token" isInvalid={isInvalid}>
              API Token
            </WizardRadioCard>
            <WizardRadioCard value="api_key" isInvalid={isInvalid}>
              API Key + Email
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
