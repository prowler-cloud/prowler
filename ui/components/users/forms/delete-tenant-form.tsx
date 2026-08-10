"use client";

import { useSession } from "next-auth/react";
import {
  Dispatch,
  FormEvent,
  SetStateAction,
  useActionState,
  useEffect,
  useState,
} from "react";

import {
  deleteTenant,
  deleteTenantThenSignOut,
  switchThenDeleteTenant,
} from "@/actions/users/tenants";
import { useToast } from "@/components/shadcn";
import { FormButtons } from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { reloadPage } from "@/lib/navigation";
import { TenantOption } from "@/types/users";

interface DeleteTenantFormProps {
  tenantId: string;
  tenantName: string;
  isActiveTenant: boolean;
  isLastTenant: boolean;
  availableTenants: TenantOption[];
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

export const DeleteTenantForm = ({
  tenantId,
  tenantName,
  isActiveTenant,
  isLastTenant,
  availableTenants,
  setIsOpen,
}: DeleteTenantFormProps) => {
  const [deleteState, deleteFormAction] = useActionState(deleteTenant, null);

  const { update } = useSession();
  const { toast } = useToast();
  const [confirmName, setConfirmName] = useState("");
  const [targetTenantId, setTargetTenantId] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const nameMatches = confirmName === tenantName;
  // Deleting the last tenant needs no switch target — there is nothing to
  // switch to; the session is closed after deletion instead.
  const needsSwitchTarget = isActiveTenant && !isLastTenant;
  const canSubmit = needsSwitchTarget
    ? nameMatches && targetTenantId !== ""
    : nameMatches;

  useEffect(() => {
    if (!deleteState) return;

    if ("success" in deleteState) {
      toast({
        title: "Organization deleted",
        description: "The organization has been permanently deleted.",
      });
      setIsOpen(false);
    } else {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: deleteState.error,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deleteState]);

  // Handle last-tenant delete: a single server action deletes the tenant and
  // closes the session, since the API also removes users whose only tenant
  // was the deleted one. On success it redirects to /sign-in server-side.
  const handleLastTenantDelete = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsSubmitting(true);

    const formData = new FormData(e.currentTarget);

    try {
      const result = await deleteTenantThenSignOut(null, formData);
      if (result && "error" in result) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.error,
        });
        setIsSubmitting(false);
      }
    } catch (error) {
      // The action redirects by throwing NEXT_REDIRECT — never a failure.
      if (
        error &&
        typeof error === "object" &&
        "digest" in error &&
        String(error.digest).startsWith("NEXT_REDIRECT")
      ) {
        return;
      }
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "The organization could not be deleted. Please try again.",
      });
      setIsSubmitting(false);
    }
  };

  // Handle active-tenant delete: call server action directly to avoid
  // React's RSC reconciliation unmounting this component before we can
  // update the session with the new tokens.
  const handleActiveTenantDelete = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsSubmitting(true);

    const formData = new FormData(e.currentTarget);
    const result = await switchThenDeleteTenant(null, formData);

    if ("success" in result) {
      await update({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
      toast({
        title: "Organization deleted",
        description: "Switching to another organization.",
      });
      reloadPage();
    } else if (result.accessToken) {
      // Partial success: switch OK but delete failed — still update session
      await update({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
      toast({
        variant: "destructive",
        title: "Switch succeeded but delete failed",
        description: result.error,
      });
      reloadPage();
    } else {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: result.error,
      });
      setIsSubmitting(false);
    }
  };

  return (
    <form
      action={isActiveTenant || isLastTenant ? undefined : deleteFormAction}
      onSubmit={
        isLastTenant
          ? handleLastTenantDelete
          : isActiveTenant
            ? handleActiveTenantDelete
            : undefined
      }
      className="flex flex-col gap-4"
    >
      <input type="hidden" name="tenantId" value={tenantId} />
      {needsSwitchTarget && targetTenantId && (
        <input type="hidden" name="targetTenantId" value={targetTenantId} />
      )}

      <div className="text-sm">
        Type <span className="font-bold">{tenantName}</span> to confirm
        deletion:
      </div>

      <Input
        value={confirmName}
        onChange={(e) => setConfirmName(e.target.value)}
        placeholder={tenantName}
        aria-label={`Type ${tenantName} to confirm deletion`}
        autoComplete="off"
      />

      {isLastTenant && (
        <div className="text-text-error-primary text-sm">
          This is your only organization. Deleting it will also remove your user
          account and close your session.
        </div>
      )}

      {needsSwitchTarget && (
        <div className="flex flex-col gap-2">
          <div className="text-sm">
            This is your active organization. Select which organization to
            switch to after deletion:
          </div>
          <Select value={targetTenantId} onValueChange={setTargetTenantId}>
            <SelectTrigger>
              <SelectValue placeholder="Select organization" />
            </SelectTrigger>
            <SelectContent>
              {availableTenants.map((tenant) => (
                <SelectItem key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      <FormButtons
        setIsOpen={setIsOpen}
        submitText={isSubmitting ? "Deleting" : "Delete"}
        loadingText="Deleting"
        submitColor="danger"
        isDisabled={!canSubmit || isSubmitting}
        rightIcon={null}
      />
    </form>
  );
};
