import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { GCPDefaultCredentials } from "@/types";

export const GCPDefaultCredentialsForm = ({
  control,
}: {
  control: Control<GCPDefaultCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Credentials
        </div>
        <div className="text-default-500 text-sm">
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
      <CustomInput
        control={control}
        name="refresh_token"
        type="password"
        label="Refresh Token"
        labelPlacement="inside"
        placeholder="Enter the Refresh Token"
        variant="bordered"
        isRequired
      />
    </>
  );
};
