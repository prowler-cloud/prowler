"use client";

import { useSession } from "next-auth/react";
import {
  Dispatch,
  SetStateAction,
  useActionState,
  useEffect,
  useState,
} from "react";

import {
  deleteTenant,
  switchTenant,
  SwitchTenantState,
} from "@/actions/users/tenants";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

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
  const [state, formAction] = useActionState(deleteTenant, null);
  const { update } = useSession();
  const { toast } = useToast();

  const [confirmName, setConfirmName] = useState("");
  const [targetTenantId, setTargetTenantId] = useState("");

  const nameMatches = confirmName === tenantName;
  const canSubmit = isActiveTenant
    ? nameMatches && targetTenantId !== ""
    : nameMatches;

  useEffect(() => {
    if (!state) return;

    const handleDelete = async () => {
      if (state.success) {
        if (isActiveTenant && targetTenantId) {
          // Active tenant deleted — switch to the target
          const fd = new FormData();
          fd.set("tenantId", targetTenantId);
          const switchResult: SwitchTenantState = await switchTenant(null, fd);

          if ("success" in switchResult) {
            await update({
              accessToken: switchResult.accessToken,
              refreshToken: switchResult.refreshToken,
            });
            toast({
              title: "Organization deleted",
              description: "Switching to another organization.",
            });
            window.location.reload();
          } else {
            toast({
              variant: "destructive",
              title: "Organization deleted, but switch failed",
              description: "Please sign out and sign back in.",
            });
            setIsOpen(false);
          }
        } else {
          // Non-active tenant — simple delete
          toast({
            title: "Organization deleted",
            description: "The organization has been permanently deleted.",
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

    handleDelete();
  }, [state, isActiveTenant, targetTenantId, update, toast, setIsOpen]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <input type="hidden" name="tenantId" value={tenantId} />

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
        submitText="Delete"
        loadingText="Deleting"
        submitColor="danger"
        isDisabled={!canSubmit}
        rightIcon={null}
      />
    </form>
  );
};
