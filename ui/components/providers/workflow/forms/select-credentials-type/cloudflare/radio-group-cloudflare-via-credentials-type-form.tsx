"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
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
          <div className="flex flex-col gap-4">
            <span className="text-default-500 text-sm">
              Select Authentication Method
            </span>
            <WizardRadioCard
              name={field.name}
              value="api_token"
              checked={(field.value || "") === "api_token"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              API Token
            </WizardRadioCard>
            <WizardRadioCard
              name={field.name}
              value="api_key"
              checked={(field.value || "") === "api_key"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              API Key + Email
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
