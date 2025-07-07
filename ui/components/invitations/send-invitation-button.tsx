"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const SendInvitationButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomLink
        path={"/invitations/new"}
        ariaLabel="Send Invitation"
        variant="solid"
        color="action"
        endContent={<AddIcon size={20} />}
      >
        Send Invitation
      </CustomLink>
    </div>
  );
};
