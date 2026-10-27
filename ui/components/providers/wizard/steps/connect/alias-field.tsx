"use client";

import { Control, FieldValues } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export function AliasField({ control }: { control: Control<FieldValues> }) {
  return (
    <WizardInputField
      control={control}
      name={ProviderCredentialFields.PROVIDER_ALIAS}
      type="text"
      label="Provider alias (optional)"
      labelPlacement="inside"
      placeholder="Enter the provider alias"
      variant="bordered"
      isRequired={false}
    />
  );
}
