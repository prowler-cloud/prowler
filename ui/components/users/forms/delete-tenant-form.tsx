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

import { deleteTenant, switchThenDeleteTenant } from "@/actions/users/tenants";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";
import { reloadPage } from "@/lib/navigation";

interface DeleteTenantFormProps {
  tenantId: string;
  tenantName: string;
  isActiveTenant: boolean;
  availableTenants: Array<{ id: string; name: string }>;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

export const DeleteTenantForm = ({
  tenantId,
  tenantName,
  isActiveTenant,
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
  const canSubmit = isActiveTenant
    ? nameMatches && targetTenantId !== ""
    : nameMatches;

  useEffect(() => {
    if (!deleteState) return;

    if (deleteState.success) {
      toast({
        title: "Organization deleted",
        description: "The organization has been permanently deleted.",
      });
      setIsOpen(false);
    } else if (deleteState.error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: deleteState.error,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deleteState]);

  // Handle active-tenant delete: call server action directly to avoid
  // React's RSC reconciliation unmounting this component before we can
  // update the session with the new tokens.
  const handleActiveTenantDelete = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsSubmitting(true);

    const formData = new FormData(e.currentTarget);
    const result = await switchThenDeleteTenant(null, formData);

    if (result.success && result.accessToken) {
      await update({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
      toast({
        title: "Organization deleted",
        description: "Switching to another organization.",
      });
      reloadPage();
    } else if (result.error) {
      if (result.accessToken) {
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
    }
  };

  return (
    <form
      action={isActiveTenant ? undefined : deleteFormAction}
      onSubmit={isActiveTenant ? handleActiveTenantDelete : undefined}
      className="flex flex-col gap-4"
    >
      <input type="hidden" name="tenantId" value={tenantId} />
      {isActiveTenant && targetTenantId && (
        <input type="hidden" name="targetTenantId" value={targetTenantId} />
      )}

      <div className="text-sm">
        Type <span className="font-bold">{tenantName}</span> to confirm
        deletion:
      </div>

      <input
        type="text"
        value={confirmName}
        onChange={(e) => setConfirmName(e.target.value)}
        placeholder={tenantName}
        className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
        autoComplete="off"
      />

      {isActiveTenant && (
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
