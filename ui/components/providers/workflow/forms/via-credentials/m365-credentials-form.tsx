import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { M365Credentials } from "@/types";

export const M365CredentialsForm = ({
  control,
}: {
  control: Control<M365Credentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="text-sm text-default-500">
          Please provide the information for your Microsoft 365 credentials.
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
        isInvalid={!!control._formState.errors.client_id}
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
        isInvalid={!!control._formState.errors.client_secret}
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
        isInvalid={!!control._formState.errors.tenant_id}
      />
      <CustomInput
        control={control}
        name="user"
        type="text"
        label="User"
        labelPlacement="inside"
        placeholder="Enter the User"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.user}
      />
      <CustomInput
        control={control}
        name="password"
        type="password"
        label="Password"
        labelPlacement="inside"
        placeholder="Enter the Password"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.password}
      />
    </>
  );
};
