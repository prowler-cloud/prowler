"use client";

import { Loader2 } from "lucide-react";
import { useState } from "react";

import { useInvitationRoles } from "@/hooks/use-invitation-roles";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { orderRolesAdminFirst } from "@/lib/invitations/order-roles";
import type { SentInvitation } from "@/types/onboarding-invite";
import type { ProviderType } from "@/types/providers";

import { AWS_CONNECT_ACTION_KIND, type AwsConnectUiState } from "../aws/types";

import { InviteTeammateForm } from "./invite-teammate-form";
import { InviteTeammateSent } from "./invite-teammate-sent";

const SEND_LABEL = "Send invitation";

interface InviteTeammatePanelProps {
  providerType: ProviderType;
  formId: string;
  onUiStateChange: (state: AwsConnectUiState) => void;
  onBusyChange: (isBusy: boolean) => void;
}

/**
 * The connect step's way out for a user who cannot connect the account: invite
 * a teammate who can. Loads the roles, sends the invitation through the wizard
 * footer and then shows the link to share. Provider-agnostic; AWS mounts it.
 */
export function InviteTeammatePanel({
  providerType,
  formId,
  onUiStateChange,
  onBusyChange,
}: InviteTeammatePanelProps) {
  const roles = useInvitationRoles();
  // Local state needed: the sent record belongs to this panel alone, never to
  // the wizard draft or the store.
  const [sent, setSent] = useState<SentInvitation | null>(null);

  if (sent) {
    return (
      <InviteTeammateSent
        invitation={sent}
        providerType={providerType}
        onUiStateChange={onUiStateChange}
      />
    );
  }

  if (roles === null) {
    return <RolesLoading onUiStateChange={onUiStateChange} />;
  }

  if (roles.length === 0) {
    return <RolesUnavailable onUiStateChange={onUiStateChange} />;
  }

  return (
    <InviteTeammateForm
      roles={orderRolesAdminFirst(roles)}
      providerType={providerType}
      formId={formId}
      onSent={(invitation) => {
        // The form unmounts mid-submit; release the step before it can.
        onBusyChange(false);
        setSent(invitation);
      }}
      onUiStateChange={onUiStateChange}
      onBusyChange={onBusyChange}
    />
  );
}

interface StaticStateProps {
  onUiStateChange: (state: AwsConnectUiState) => void;
}

function RolesLoading({ onUiStateChange }: StaticStateProps) {
  useMountEffect(() => {
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: SEND_LABEL,
      actionDisabled: true,
      isLoading: false,
      actionKind: AWS_CONNECT_ACTION_KIND.SUBMIT,
    });
  });

  return (
    <p
      role="status"
      className="text-text-neutral-secondary flex items-center gap-2 text-sm"
    >
      <Loader2 aria-hidden className="size-4 animate-spin" />
      Loading roles...
    </p>
  );
}

function RolesUnavailable({ onUiStateChange }: StaticStateProps) {
  useMountEffect(() => {
    onUiStateChange({
      showBack: true,
      showAction: false,
      actionLabel: SEND_LABEL,
      actionDisabled: true,
      isLoading: false,
      actionKind: AWS_CONNECT_ACTION_KIND.SUBMIT,
    });
  });

  return (
    <p className="text-text-neutral-secondary text-sm">
      Roles could not be loaded right now. You can invite your team later from
      the Invitations page.
    </p>
  );
}
