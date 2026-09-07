"use client";

import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { AzureClientSecretCredentials } from "@/types";

export const AzureServicePrincipalCredentialsForm = ({
  control,
}: {
  control: Control<AzureClientSecretCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Service Principal with Client Secret
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Please provide the Azure Service Principal credentials issued from
          your App Registration&apos;s <em>Certificates &amp; secrets</em>{" "}
          blade.
        </div>
      </div>
      <WizardInputField
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
      />
      <WizardInputField
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
      />
      <WizardInputField
        control={control}
        name="client_secret"
        type="password"
        label="Client Secret"
        labelPlacement="inside"
        placeholder="Enter the Client Secret"
        variant="bordered"
        isRequired
      />
    </>
  );
};
