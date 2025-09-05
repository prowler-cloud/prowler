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
    if (state && "success" in state) {
      toast({
        title: "Changed successfully",
        description: state.success,
      });
      setIsOpen(false);
    } else if (state && "error" in state) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: state.error,
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
        isInvalid={!!(state && "error" in state)}
        errorMessage={state && "error" in state ? state.error : undefined}
      />

      {/* Hidden inputs for Server Action */}
      <input type="hidden" name="tenantId" value={tenantId} />
      <input type="hidden" name="currentName" value={tenantName || ""} />

      <FormButtons setIsOpen={setIsOpen} />
    </form>
  );
};
