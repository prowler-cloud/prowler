"use client";

import { Dispatch, SetStateAction, useTransition } from "react";

import { removeUserFromTenant } from "@/actions/users/users";
import { DeleteIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";

interface ExpelUserFormProps {
  userId: string;
  userName?: string;
  tenantId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

export const ExpelUserForm = ({
  userId,
  userName,
  tenantId,
  setIsOpen,
}: ExpelUserFormProps) => {
  const { toast } = useToast();
  const [isPending, startTransition] = useTransition();

  const handleExpel = () => {
    startTransition(async () => {
      const formData = new FormData();
      formData.append("userId", userId);
      formData.append("tenantId", tenantId);

      const data = await removeUserFromTenant(formData);

      if (!data || !("success" in data) || data.success !== true) {
        const detail =
          data && "errors" in data && data.errors?.[0]?.detail
            ? data.errors[0].detail
            : "Failed to expel the user";
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: detail,
        });
        return;
      }

      toast({
        title: "User expelled",
        description: `${userName ?? "The user"} was removed from this organization.`,
      });
      setIsOpen(false);
    });
  };

  const displayName = userName ?? "this user";

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm">
        <span className="font-semibold">{displayName}</span> will lose access to
        this organization. If they don&apos;t belong to any other organization,
        their account will be permanently deleted.
      </p>

      <div className="flex w-full justify-end gap-4">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => setIsOpen(false)}
          disabled={isPending}
        >
          Cancel
        </Button>
        <Button
          type="button"
          variant="destructive"
          size="lg"
          onClick={handleExpel}
          disabled={isPending}
        >
          {!isPending && <DeleteIcon size={24} aria-hidden="true" />}
          {isPending ? "Expelling…" : "Expel user"}
        </Button>
      </div>
    </div>
  );
};
