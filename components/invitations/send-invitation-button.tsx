"use client";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";

export const SendInvitationButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomButton
        asLink="/invitations/new"
        ariaLabel="Send Invitation"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Send Invitation
      </CustomButton>
    </div>
  );
};
