import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { OpenStackCredentials } from "@/types";

export const OpenStackCredentialsForm = ({
  control,
}: {
  control: Control<OpenStackCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Clouds YAML
        </div>
        <div className="text-default-500 text-sm">
          Please provide your OpenStack clouds.yaml content and the cloud name.
        </div>
      </div>
      <CustomTextarea
        control={control}
        name="clouds_yaml_content"
        label="Clouds YAML Content"
        labelPlacement="inside"
        placeholder="Paste your clouds.yaml content here"
        variant="bordered"
        minRows={10}
        isRequired
      />
      <CustomInput
        control={control}
        name="clouds_yaml_cloud"
        type="text"
        label="Cloud Name"
        labelPlacement="inside"
        placeholder="e.g. mycloud"
        variant="bordered"
        isRequired
      />
    </>
  );
};
