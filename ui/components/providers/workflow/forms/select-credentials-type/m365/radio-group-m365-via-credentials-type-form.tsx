"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
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
          <div className="flex flex-col gap-4">
            <span className="text-default-500 text-sm">
              Select Authentication Method
            </span>
            <WizardRadioCard
              name={field.name}
              value="app_client_secret"
              checked={(field.value || "") === "app_client_secret"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              App Client Secret Credentials
            </WizardRadioCard>
            <WizardRadioCard
              name={field.name}
              value="app_certificate"
              checked={(field.value || "") === "app_certificate"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              App Certificate Credentials
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
