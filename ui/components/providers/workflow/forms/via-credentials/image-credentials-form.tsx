import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
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
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.REGISTRY_USERNAME}
        label="Registry Username (Optional)"
        labelPlacement="inside"
        placeholder="Username for registry authentication"
        variant="bordered"
        type="text"
        isRequired={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.REGISTRY_PASSWORD}
        label="Registry Password (Optional)"
        labelPlacement="inside"
        placeholder="Password for registry authentication"
        variant="bordered"
        type="password"
        isRequired={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.REGISTRY_TOKEN}
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
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.IMAGE_FILTER}
        label="Image Filter (Optional)"
        labelPlacement="inside"
        placeholder="e.g. ^prod/.*"
        variant="bordered"
        type="text"
        isRequired={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.TAG_FILTER}
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
