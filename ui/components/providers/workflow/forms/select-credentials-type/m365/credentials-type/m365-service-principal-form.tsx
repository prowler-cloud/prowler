import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { M365Credentials } from "@/types";

export const M365ServicePrincipalForm = ({
  control,
}: {
  control: Control<M365Credentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Application/Service Principal
        </div>
        <div className="text-sm text-default-500">
          Please provide the Application/Service Principal information for your
          Microsoft 365 tenant.
        </div>
      </div>

      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLIENT_ID}
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.CLIENT_ID]
        }
      />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLIENT_SECRET}
        type="password"
        label="Client Secret"
        labelPlacement="inside"
        placeholder="Enter the Client Secret"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.CLIENT_SECRET]
        }
      />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.TENANT_ID}
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.TENANT_ID]
        }
      />
    </>
  );
};
