"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { FormMessage } from "@/components/shadcn/form";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";

// The `via` values shared with the M365 flow (they both authenticate against
// an Entra ID App Registration and reuse the same wizard state machine).
// Exposed as a const object so consumers can reference the values by name
// instead of duplicating string literals — matches the AWS/M365 patterns
// (`AWS_CREDENTIAL_OPTIONS`, `M365_CREDENTIAL_OPTIONS`).
export const AZURE_CREDENTIALS_TYPES = {
  CERTIFICATE: "app_certificate",
  CLIENT_SECRET: "app_client_secret",
  EMPTY: "",
} as const;

type AzureCredentialsType =
  (typeof AZURE_CREDENTIALS_TYPES)[keyof typeof AZURE_CREDENTIALS_TYPES];

// Local form shape for this selector: only the radio value lives here, the
// actual credential fields belong to the downstream credentials form. Kept
// exported so `SelectViaAzure` and the tests bind the same type instead of
// falling back to `any`.
export type AzureCredentialsTypeFormValues = {
  azureCredentialsType: AzureCredentialsType;
};

type RadioGroupAzureViaCredentialsFormProps = {
  control: Control<AzureCredentialsTypeFormValues>;
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
