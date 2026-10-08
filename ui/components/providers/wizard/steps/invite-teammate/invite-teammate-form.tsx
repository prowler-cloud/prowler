"use client";

import { useEffect } from "react";
import { Controller } from "react-hook-form";

import { useSendInvitation } from "@/components/invitations/workflow/forms/use-send-invitation";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Form } from "@/components/shadcn/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { isAdminRole } from "@/lib/invitations/order-roles";
import {
  INVITATION_SOURCE,
  type InvitationRoleOption,
  type SentInvitation,
} from "@/types/onboarding-invite";
import { getProviderDisplayName, type ProviderType } from "@/types/providers";

import { AWS_CONNECT_ACTION_KIND, type AwsConnectUiState } from "../aws/types";

interface InviteTeammateFormProps {
  roles: InvitationRoleOption[];
  providerType: ProviderType;
  formId: string;
  onSent: (invitation: SentInvitation) => void;
  onUiStateChange: (state: AwsConnectUiState) => void;
  onBusyChange: (isBusy: boolean) => void;
}

/** Email and role for the teammate; the wizard footer submits it by `formId`. */
export function InviteTeammateForm({
  roles,
  providerType,
  formId,
  onSent,
  onUiStateChange,
  onBusyChange,
}: InviteTeammateFormProps) {
  const { form, onSubmit, isSubmitting, isValid } = useSendInvitation({
    source: INVITATION_SOURCE.PROVIDER_CONNECT,
    // Admin can finish the setup; the user may still pick another role.
    defaultRoleId: roles.find(isAdminRole)?.id ?? "",
    mode: "onChange",
    onSuccess: onSent,
  });

  // Same contract the AWS forms use: the wizard footer lives outside the step.
  // Both callbacks must be stable setters, or this effect would loop.
  useEffect(() => {
    onBusyChange(isSubmitting);
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: isSubmitting ? "Sending invitation..." : "Send invitation",
      actionDisabled: !isValid || isSubmitting,
      isLoading: isSubmitting,
      actionKind: AWS_CONNECT_ACTION_KIND.SUBMIT,
    });
  }, [isSubmitting, isValid, onBusyChange, onUiStateChange]);

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-4">
        <p className="text-text-neutral-secondary text-sm">
          Invite someone from your team who can access the{" "}
          {getProviderDisplayName(providerType)} account. They will join this
          Prowler tenant and can connect it themselves.
        </p>

        <WizardInputField
          control={form.control}
          name="email"
          type="email"
          label="Teammate email"
          labelPlacement="inside"
          placeholder="name@company.com"
          variant="bordered"
          isRequired
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />

        <Controller
          name="roleId"
          control={form.control}
          render={({ field, fieldState }) => (
            <div className="flex flex-col gap-1.5">
              <Select
                value={field.value || undefined}
                onValueChange={field.onChange}
                disabled={isSubmitting}
              >
                <SelectTrigger aria-label="Select a role">
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {roles.map((role) => (
                    <SelectItem key={role.id} value={role.id}>
                      {role.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-text-neutral-tertiary text-xs">
                Pick a role that can manage providers, such as admin.
              </p>
              {fieldState.error && (
                <p className="text-text-error text-sm">
                  {fieldState.error.message}
                </p>
              )}
            </div>
          )}
        />
      </form>
    </Form>
  );
}
