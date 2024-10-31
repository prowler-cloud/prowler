import { Control, FieldErrors } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";

import { AzureCredentials } from "../../../../../types";

interface AzureCredentialsFormProps {
  control: Control<AzureCredentials>;
}

export const AzureCredentialsForm = ({
  control,
}: AzureCredentialsFormProps) => {
  return (
    <>
      <div className="text-left">
        <div className="text-2xl font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="py-2 text-default-500">
          Please provide the information for your Azure credentials.
        </div>
      </div>
      <CustomInput
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
        isInvalid={
          !!(control._formState.errors as FieldErrors<AzureCredentials>)
            .client_id
        }
      />
      <CustomInput
        control={control}
        name="client_secret"
        type="text"
        label="Client Secret"
        labelPlacement="inside"
        placeholder="Enter the Client Secret"
        variant="bordered"
        isRequired
        isInvalid={
          !!(control._formState.errors as FieldErrors<AzureCredentials>)
            .client_secret
        }
      />
      <CustomInput
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
        isInvalid={
          !!(control._formState.errors as FieldErrors<AzureCredentials>)
            .tenant_id
        }
      />
    </>
  );
};
