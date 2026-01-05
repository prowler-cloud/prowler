import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { IacCredentials } from "@/types";

export const IacCredentialsForm = ({
  control,
}: {
  control: Control<IacCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Repository
        </div>
        <div className="text-default-500 text-sm">
          Provide an access token if the repository is private (optional).
        </div>
      </div>
      <CustomInput
        control={control}
        name="access_token"
        label="Access Token (Optional)"
        labelPlacement="inside"
        placeholder="Token for private repositories (optional)"
        variant="bordered"
        type="password"
        isRequired={false}
      />
    </>
  );
};
