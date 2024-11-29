"use client";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";

export const AddUserButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomButton
        asLink="/invitations/new"
        ariaLabel="Invite User"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Invite User
      </CustomButton>
    </div>
  );
};
