"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const AddUserButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomLink
        href="/invitations/new"
        ariaLabel="Invite User"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Invite User
      </CustomLink>
    </div>
  );
};
