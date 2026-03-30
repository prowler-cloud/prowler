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
import { reloadPage } from "@/lib/navigation";

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

    let cancelled = false;

    const handleCreate = async () => {
      if ("success" in state) {
        // Two-step: create succeeded, now switch to the new tenant
        const fd = new FormData();
        fd.set("tenantId", state.tenantId);
        const switchResult: SwitchTenantState = await switchTenant(null, fd);

        if (cancelled) return;

        if ("success" in switchResult) {
          await update({
            accessToken: switchResult.accessToken,
            refreshToken: switchResult.refreshToken,
          });
          toast({
            title: "Organization created",
            description: "Switching to the new organization.",
          });
          reloadPage();
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
      } else {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: state.error,
        });
      }
    };

    handleCreate();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <CustomServerInput
        name="name"
        label="Organization name"
        placeholder="Enter organization name"
        labelPlacement="outside"
        variant="bordered"
        isRequired={true}
        isInvalid={!!(state && "error" in state)}
        errorMessage={state && "error" in state ? state.error : undefined}
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
