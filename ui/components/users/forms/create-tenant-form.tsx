"use client";

import { useSession } from "next-auth/react";
import { Dispatch, SetStateAction, useActionState, useEffect } from "react";

import {
  createTenant,
  switchTenant,
  SwitchTenantState,
} from "@/actions/users/tenants";
import { useToast } from "@/components/ui";
import { CustomServerInput } from "@/components/ui/custom";
import { FormButtons } from "@/components/ui/form";

export const CreateTenantForm = ({
  setIsOpen,
}: {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const [state, formAction] = useActionState(createTenant, null);
  const { update } = useSession();
  const { toast } = useToast();

  useEffect(() => {
    if (!state) return;

    const handleCreate = async () => {
      if (state.success && state.tenantId) {
        // Two-step: create succeeded, now switch to the new tenant
        const fd = new FormData();
        fd.set("tenantId", state.tenantId);
        const switchResult: SwitchTenantState = await switchTenant(null, fd);

        if ("success" in switchResult) {
          await update({
            accessToken: switchResult.accessToken,
            refreshToken: switchResult.refreshToken,
          });
          toast({
            title: "Organization created",
            description: "Switching to the new organization.",
          });
          window.location.reload();
        } else {
          // Create succeeded but switch failed — org exists, user can switch manually
          toast({
            variant: "destructive",
            title: "Organization created, but switch failed",
            description:
              switchResult.error ||
              "You can switch manually from the organizations list.",
          });
          setIsOpen(false);
        }
      } else if (state.error) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: state.error,
        });
      }
    };

    handleCreate();
  }, [state, update, toast, setIsOpen]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <CustomServerInput
        name="name"
        label="Organization name"
        placeholder="Enter organization name"
        labelPlacement="outside"
        variant="bordered"
        isRequired={true}
        isInvalid={!!(state && state.error)}
        errorMessage={state?.error}
      />

      <FormButtons
        setIsOpen={setIsOpen}
        submitText="Create"
        loadingText="Creating"
        rightIcon={null}
      />
    </form>
  );
};
