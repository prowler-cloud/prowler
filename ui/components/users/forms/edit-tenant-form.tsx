"use client";

import { Dispatch, SetStateAction, useEffect } from "react";
import { useFormState } from "react-dom";

import { updateTenantName } from "@/actions/users/tenants";
import { useToast } from "@/components/ui";
import { CustomServerInput } from "@/components/ui/custom";
import { FormButtons } from "@/components/ui/form";

export const EditTenantForm = ({
  tenantId,
  tenantName,
  setIsOpen,
}: {
  tenantId: string;
  tenantName?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const [state, formAction] = useFormState(updateTenantName, null);
  const { toast } = useToast();

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Changed successfully",
        description: state.success,
      });
      setIsOpen(false);
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: state.errors.general,
      });
    }
  }, [state, toast, setIsOpen]);

  return (
    <form action={formAction} className="flex flex-col space-y-4">
      <div className="text-md">
        Current name: <span className="font-bold">{tenantName}</span>
      </div>

      <CustomServerInput
        name="name"
        label="Organization name"
        placeholder="Enter the new name"
        labelPlacement="outside"
        variant="bordered"
        isRequired={true}
        isInvalid={!!state?.errors?.name}
        errorMessage={state?.errors?.name}
      />

      {/* Hidden inputs for Server Action */}
      <input type="hidden" name="tenantId" value={tenantId} />
      <input type="hidden" name="currentName" value={tenantName || ""} />

      <FormButtons setIsOpen={setIsOpen} />
    </form>
  );
};
