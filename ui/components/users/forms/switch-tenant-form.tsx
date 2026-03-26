"use client";

import { useSession } from "next-auth/react";
import { Dispatch, SetStateAction, useActionState, useEffect } from "react";

import { switchTenant } from "@/actions/users/tenants";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

export const SwitchTenantForm = ({
  tenantId,
  setIsOpen,
}: {
  tenantId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const [state, formAction] = useActionState(switchTenant, null);
  const { update } = useSession();
  const { toast } = useToast();
  useEffect(() => {
    if (!state) return;

    const handleSwitch = async () => {
      if ("success" in state) {
        await update({
          accessToken: state.accessToken,
          refreshToken: state.refreshToken,
        });
        toast({
          title: "Organization switched",
          description: "The page will reload to apply the change.",
        });
        window.location.reload();
      } else {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: state.error,
        });
        setIsOpen(false);
      }
    };

    handleSwitch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return (
    <form action={formAction}>
      <input type="hidden" name="tenantId" value={tenantId} />
      <FormButtons
        setIsOpen={setIsOpen}
        submitText="Confirm"
        loadingText="Switching"
        rightIcon={null}
      />
    </form>
  );
};
