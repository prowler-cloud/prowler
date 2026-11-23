"use client";

import { Control, useWatch } from "react-hook-form";

import { WizardTextareaField } from "@/components/providers/workflow/forms/fields";
import { KubernetesCredentials } from "@/types";
import {
  KUBECONFIG_NON_INLINE_CREDENTIALS_ERROR,
  kubeconfigIsInlineOnlyCredentials,
} from "@/types/formSchemas";

export const KubernetesCredentialsForm = ({
  control,
}: {
  control: Control<KubernetesCredentials>;
}) => {
  const kubeconfigContent = useWatch({
    control,
    name: "kubeconfig_content",
  });
  const hasUnsupportedCredentials = !kubeconfigIsInlineOnlyCredentials(
    kubeconfigContent ?? "",
  );

  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via Credentials
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Please provide the kubeconfig content for your Kubernetes credentials.
        </div>
      </div>
      <WizardTextareaField
        control={control}
        name="kubeconfig_content"
        label="Kubeconfig Content"
        labelPlacement="inside"
        placeholder="Paste your Kubeconfig YAML content here"
        variant="bordered"
        minRows={10}
        isRequired
      />
      {hasUnsupportedCredentials && (
        <p className="text-text-error-primary text-xs">
          {KUBECONFIG_NON_INLINE_CREDENTIALS_ERROR}
        </p>
      )}
    </>
  );
};
