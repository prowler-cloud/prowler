"use client";

import { CircleCheck } from "lucide-react";

import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { buildInvitationAcceptLink } from "@/lib/invitations/accept-link";
import { isCloud } from "@/lib/shared/env";
import type { SentInvitation } from "@/types/onboarding-invite";
import { getProviderDisplayName, type ProviderType } from "@/types/providers";

import { AWS_CONNECT_ACTION_KIND, type AwsConnectUiState } from "../aws/types";

interface InviteTeammateSentProps {
  invitation: SentInvitation;
  providerType: ProviderType;
  onUiStateChange: (state: AwsConnectUiState) => void;
}

/** The link to share once the invitation exists; the footer's "Done" closes the wizard. */
export function InviteTeammateSent({
  invitation,
  providerType,
  onUiStateChange,
}: InviteTeammateSentProps) {
  useMountEffect(() => {
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: "Done",
      actionDisabled: false,
      isLoading: false,
      actionKind: AWS_CONNECT_ACTION_KIND.CLOSE,
    });
  });

  // Mounted after a click, so the window is there; the guard keeps SSR safe.
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  const link = buildInvitationAcceptLink(invitation.token, origin);

  return (
    <section role="status" className="flex flex-col gap-4">
      <div className="flex items-start gap-3">
        <CircleCheck
          aria-hidden
          className="text-text-success-primary size-5 shrink-0"
        />
        <div className="flex min-w-0 flex-col gap-1">
          <h4 className="text-sm font-semibold break-words">
            Invitation sent to {invitation.email}
          </h4>
          <p className="text-text-neutral-secondary text-sm">
            {isCloud()
              ? "We have emailed them the invitation. You can also share this link with them:"
              : "Prowler does not send emails. Share this link with them:"}
          </p>
        </div>
      </div>

      <CodeSnippet value={link} className="max-w-full" />

      <p className="text-text-neutral-secondary text-sm">
        The link expires in 7 days. Once they accept, they can connect the{" "}
        {getProviderDisplayName(providerType)} account from the Providers page.
      </p>
    </section>
  );
}
