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
  switchThenDeleteTenant,
  SwitchThenDeleteTenantState,
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
  // Two hooks: one for simple delete, one for switch-then-delete.
  // Both are always called (hook rules), but only the relevant one is used.
  const [deleteState, deleteFormAction] = useActionState(deleteTenant, null);
  const [switchDeleteState, switchDeleteFormAction] = useActionState(
    switchThenDeleteTenant,
    null,
  );

  const state: SwitchThenDeleteTenantState | null = isActiveTenant
    ? switchDeleteState
    : deleteState;
  const formAction = isActiveTenant ? switchDeleteFormAction : deleteFormAction;

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

    const handleResult = async () => {
      if (state.success) {
        if (state.accessToken) {
          // Active tenant: switch + delete succeeded — update session and reload
          await update({
            accessToken: state.accessToken,
            refreshToken: state.refreshToken,
          });
          toast({
            title: "Organization deleted",
            description: "Switching to another organization.",
          });
          reloadPage();
        } else {
          // Non-active tenant — simple delete
          toast({
            title: "Organization deleted",
            description: "The organization has been permanently deleted.",
          });
          setIsOpen(false);
        }
      } else if (state.error) {
        if (state.accessToken) {
          // Partial success: switch OK but delete failed — still update session
          await update({
            accessToken: state.accessToken,
            refreshToken: state.refreshToken,
          });
          toast({
            variant: "destructive",
            title: "Switch succeeded but delete failed",
            description: state.error,
          });
          reloadPage();
        } else {
          toast({
            variant: "destructive",
            title: "Oops! Something went wrong",
            description: state.error,
          });
        }
      }
    };

    handleResult();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
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
        submitText="Delete"
        loadingText="Deleting"
        submitColor="danger"
        isDisabled={!canSubmit}
        rightIcon={null}
      />
    </form>
  );
};
