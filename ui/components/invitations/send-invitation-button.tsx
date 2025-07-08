"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const SendInvitationButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomLink
        href={"/invitations/new"}
        ariaLabel="Send Invitation"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Send Invitation
      </CustomLink>
    </div>
  );
};
