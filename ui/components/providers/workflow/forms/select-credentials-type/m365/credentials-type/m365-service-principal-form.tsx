import Link from "next/link";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { M365Credentials } from "@/types";

export const M365ServicePrincipalForm = ({
  control,
  setValue,
}: {
  control: Control<M365Credentials>;
  setValue: UseFormSetValue<M365Credentials>;
  externalId: string;
}) => {
  const credentialsType = useWatch({
    control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
    defaultValue: "m365-service-principal",
  });

  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect using Application/Service Principal
        </div>
        <div className="text-sm text-default-500">
          Please provide the information for your Microsoft 365 Service Principal.
        </div>
      </div>

      <span className="text-xs font-bold text-default-500">Authentication</span>

      <Select
        name={ProviderCredentialFields.CREDENTIALS_TYPE}
        label="Authentication Method"
        placeholder="Select credentials type"
        defaultSelectedKeys={["m365-service-principal"]}
        className="mb-4"
        variant="bordered"
        onSelectionChange={(keys) =>
          setValue(
            ProviderCredentialFields.CREDENTIALS_TYPE,
            Array.from(keys)[0] as "m365-service-principal" | "m365-user-credentials",
          )
        }
      >
        <SelectItem key="m365-service-principal">Application/Service Principal</SelectItem>
        <SelectItem key="m365-user-credentials">User credentials</SelectItem>
      </Select>

      {credentialsType === "m365-service-principal" && (
        <>
          <CustomInput
            control={control}
            name={ProviderCredentialFields.CLIENT_ID}
            type="text"
            label="Client ID"
            labelPlacement="inside"
            placeholder="Enter the Client ID"
            variant="bordered"
            isRequired
            isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_ID]}
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
            isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_SECRET]}
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
            isInvalid={!!control._formState.errors[ProviderCredentialFields.TENANT_ID]}
          />
        </>
      )}

      {credentialsType === "m365-user-credentials" && (
        <>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLIENT_ID}
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_ID]}
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
        isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_SECRET]}
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
        isInvalid={!!control._formState.errors[ProviderCredentialFields.TENANT_ID]}
      />
      </>
      )}
    </>
  );
};
