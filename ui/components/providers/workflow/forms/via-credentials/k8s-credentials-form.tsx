import { Control } from "react-hook-form";

import { CustomTextarea } from "@/components/ui/custom";
import { KubernetesCredentials } from "@/types";

export const KubernetesCredentialsForm = ({
  control,
}: {
  control: Control<KubernetesCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="text-sm text-default-500">
          Please provide the kubeconfig content for your Kubernetes credentials.
        </div>
      </div>
      <CustomTextarea
        control={control}
        name="kubeconfig_content"
        label="Kubeconfig Content"
        labelPlacement="inside"
        placeholder="Paste your Kubeconfig YAML content here"
        variant="bordered"
        minRows={10}
        isRequired
        isInvalid={!!control._formState.errors.kubeconfig_content}
      />
    </>
  );
};
