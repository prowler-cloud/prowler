"use client";

import { SendInvitationForm } from "@/components/invitations/workflow/forms/send-invitation-form";
import { Button } from "@/components/shadcn";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal/modal";
import {
  INVITATION_SOURCE,
  type InvitationRoleOption,
} from "@/types/onboarding-invite";

interface OnboardingInviteDialogProps {
  open: boolean;
  roles: InvitationRoleOption[];
  onSent: (invitationId: string) => void;
  onSkip: () => void;
}

const DEFAULT_ROLE_NAME = "admin";

// Roles are listed with the admin one first so it is the natural pick for a
// first teammate; the form itself keeps the selection required.
const orderRoles = (roles: InvitationRoleOption[]) =>
  [...roles].sort((a, b) =>
    a.name.toLowerCase() === DEFAULT_ROLE_NAME
      ? -1
      : b.name.toLowerCase() === DEFAULT_ROLE_NAME
        ? 1
        : 0,
  );

// "Invite your team", offered once right after the first provider is
// connected: permissions on the cloud were just granted and the value of
// sharing the first scan is fresh. Reuses the members-page form, tagged as an
// onboarding invitation.
export function OnboardingInviteDialog({
  open,
  roles,
  onSent,
  onSkip,
}: OnboardingInviteDialogProps) {
  const hasRoles = roles.length > 0;

  return (
    <Modal
      open={open}
      title="Invite your team"
      description="Security is a team effort. Invite a teammate now so they see the first scan with you. You can skip this."
      size="lg"
      // Overlay/Escape/X counts as a skip — the caller persists the marker once.
      onOpenChange={(next) => {
        if (!next) onSkip();
      }}
    >
      <div className="flex flex-col gap-4">
        {hasRoles ? (
          <SendInvitationForm
            roles={orderRoles(roles)}
            isSelectorDisabled={false}
            source={INVITATION_SOURCE.ONBOARDING}
            onSuccess={onSent}
          />
        ) : (
          <p className="text-text-neutral-secondary text-sm">
            Roles could not be loaded right now. You can invite your team later
            from the Invitations page.
          </p>
        )}
        <DialogFooter>
          {/* Outline matches the app's modal secondary action (e.g. Launch Scan's Cancel). */}
          <Button type="button" variant="outline" onClick={onSkip}>
            Skip for now
          </Button>
        </DialogFooter>
      </div>
    </Modal>
  );
}
