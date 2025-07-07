"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const AddUserButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomLink
        path="/invitations/new"
        ariaLabel="Invite User"
        variant="solid"
        color="action"
        endContent={<AddIcon size={20} />}
      >
        Invite User
      </CustomLink>
    </div>
  );
};
