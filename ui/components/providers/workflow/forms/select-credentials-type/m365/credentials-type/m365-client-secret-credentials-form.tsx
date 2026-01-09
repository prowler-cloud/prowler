"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { M365ClientSecretCredentials } from "@/types";

export const M365ClientSecretCredentialsForm = ({
  control,
}: {
  control: Control<M365ClientSecretCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          App Client Secret Credentials
        </div>
        <div className="text-default-500 text-sm">
          Please provide your Microsoft 365 application credentials.
        </div>
      </div>
      <CustomInput
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
      />
      <CustomInput
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
