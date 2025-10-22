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
          Please provide the repository URL to scan for Infrastructure as Code
          files.
        </div>
      </div>
      <CustomInput
        control={control}
        name="repository_url"
        label="Repository URL"
        labelPlacement="inside"
        placeholder="https://github.com/user/repo or https://github.com/user/repo.git"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.repository_url}
      />
      <CustomInput
        control={control}
        name="access_token"
        label="Access Token (Optional)"
        labelPlacement="inside"
        placeholder="Token for private repositories (optional)"
        variant="bordered"
        type="password"
        isInvalid={!!control._formState.errors.access_token}
      />
    </>
  );
};
