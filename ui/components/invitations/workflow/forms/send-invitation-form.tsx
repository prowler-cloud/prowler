"use client";

import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { Controller } from "react-hook-form";

import { Button } from "@/components/shadcn";
import { CustomInput } from "@/components/shadcn/custom";
import { Form } from "@/components/shadcn/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import type { InvitationRoleOption } from "@/types/onboarding-invite";

import { useSendInvitation } from "./use-send-invitation";

interface SendInvitationFormProps {
  roles: InvitationRoleOption[];
  defaultRole?: string;
  isSelectorDisabled: boolean;
  // Where the invitation was sent from, forwarded to the API as `?source=`
  // so the origin can be told apart (e.g. the onboarding invite step).
  source?: string;
  // Replaces the default navigation to the invitation details page.
  onSuccess?: (invitationId: string) => void;
}

export const SendInvitationForm = ({
  roles = [],
  defaultRole = "admin",
  isSelectorDisabled = false,
  source,
  onSuccess,
}: SendInvitationFormProps) => {
  const router = useRouter();

  const { form, onSubmit, isSubmitting } = useSendInvitation({
    source,
    defaultRoleId: isSelectorDisabled ? defaultRole : "",
    onSuccess: (invitation) => {
      if (onSuccess) {
        onSuccess(invitation.id);
        return;
      }
      router.push(`/invitations/check-details/?id=${invitation.id}`);
    },
  });

  return (
    <Form {...form}>
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        {/* Email Field */}
        <CustomInput
          control={form.control}
          name="email"
          type="email"
          label="Email"
          labelPlacement="inside"
          placeholder="Enter the email address"
          variant="flat"
          isRequired
        />

        <Controller
          name="roleId"
          control={form.control}
          render={({ field }) => (
            <div className="flex flex-col gap-1.5">
              <Select
                value={field.value || undefined}
                onValueChange={field.onChange}
                disabled={isSelectorDisabled}
              >
                <SelectTrigger aria-label="Select a role">
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {isSelectorDisabled ? (
                    <SelectItem value={defaultRole}>{defaultRole}</SelectItem>
                  ) : (
                    roles.map((role) => (
                      <SelectItem key={role.id} value={role.id}>
                        {role.name}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              {form.formState.errors.roleId && (
                <p className="text-text-error mt-2 text-sm">
                  {form.formState.errors.roleId.message}
                </p>
              )}
            </div>
          )}
        />

        {/* Submit Button */}
        <div className="flex w-full justify-end sm:gap-6">
          <Button
            type="submit"
            className="w-1/2"
            variant="default"
            size="lg"
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>Loading</>
            ) : (
              <>
                <SaveIcon size={20} />
                <span>Send Invitation</span>
              </>
            )}
          </Button>
        </div>
      </form>
    </Form>
  );
};
