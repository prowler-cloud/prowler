import { Control } from "react-hook-form";

import { CustomTextarea } from "@/components/ui/custom";
import { GCPServiceAccountKey } from "@/types";

export const GCPServiceAccountKeyForm = ({
  control,
}: {
  control: Control<GCPServiceAccountKey>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via Service Account Key
        </div>
        <div className="text-sm text-default-500">
          Please provide the service account key for your GCP credentials.
        </div>
      </div>
      <CustomTextarea
        control={control}
        name="service_account_key"
        label="Service Account Key"
        labelPlacement="inside"
        placeholder="Paste your Service Account Key JSON content here"
        variant="bordered"
        minRows={10}
        isRequired
        isInvalid={!!control._formState.errors.service_account_key}
      />
    </>
  );
};
