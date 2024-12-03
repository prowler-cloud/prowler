import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { GCPCredentials } from "@/types";

export const GCPcredentialsForm = ({
  control,
}: {
  control: Control<GCPCredentials>;
}) => {
  return (
    <>
      <div className="text-left">
        <div className="text-2xl font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="py-2 text-default-500">
          Please provide the information for your GCP credentials.
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
        name="refresh_token"
        type="password"
        label="Refresh Token"
        labelPlacement="inside"
        placeholder="Enter the Refresh Token"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.refresh_token}
      />
    </>
  );
};
