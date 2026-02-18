import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ImageCredentials } from "@/types";

export const ImageCredentialsForm = ({
  control,
}: {
  control: Control<ImageCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Registry Credentials
        </div>
        <div className="text-default-500 text-sm">
          Provide registry credentials to authenticate with your container
          registry (all fields are optional).
        </div>
      </div>
      <CustomInput
        control={control}
        name="registry_username"
        label="Registry Username (Optional)"
        labelPlacement="inside"
        placeholder="Username for registry authentication"
        variant="bordered"
        type="text"
        isRequired={false}
      />
      <CustomInput
        control={control}
        name="registry_password"
        label="Registry Password (Optional)"
        labelPlacement="inside"
        placeholder="Password for registry authentication"
        variant="bordered"
        type="password"
        isRequired={false}
      />
      <CustomInput
        control={control}
        name="registry_token"
        label="Registry Token (Optional)"
        labelPlacement="inside"
        placeholder="Token for registry authentication"
        variant="bordered"
        type="password"
        isRequired={false}
      />

      <div className="flex flex-col pt-2">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Scan Scope
        </div>
        <div className="text-default-500 text-sm">
          Limit which repositories and tags are scanned using regex patterns.
        </div>
      </div>
      <CustomInput
        control={control}
        name="image_filter"
        label="Image Filter (Optional)"
        labelPlacement="inside"
        placeholder="e.g. ^prod/.*"
        variant="bordered"
        type="text"
        isRequired={false}
      />
      <CustomInput
        control={control}
        name="tag_filter"
        label="Tag Filter (Optional)"
        labelPlacement="inside"
        placeholder="e.g. ^(latest|v\d+\.\d+\.\d+)$"
        variant="bordered"
        type="text"
        isRequired={false}
      />
    </>
  );
};
