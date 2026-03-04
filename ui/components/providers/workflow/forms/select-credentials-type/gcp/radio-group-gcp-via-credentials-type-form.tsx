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

export const RadioGroupGCPViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupAWSViaCredentialsFormProps) => {
  return (
    <Controller
      name="gcpCredentialsType"
      control={control}
      render={({ field }) => (
        <>
          <div className="flex flex-col gap-4">
            <span className="text-default-500 text-sm">
              Using Service Account
            </span>
            <WizardRadioCard
              name={field.name}
              value="service-account"
              checked={(field.value || "") === "service-account"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              Connect via Service Account Key
            </WizardRadioCard>
            <span className="text-default-500 text-sm">
              Using Application Default Credentials
            </span>
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
              Connect via Application Default Credentials
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
