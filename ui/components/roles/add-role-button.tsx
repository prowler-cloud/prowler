"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const AddRoleButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomLink
        href="/roles/new"
        ariaLabel="Add Role"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Add Role
      </CustomLink>
    </div>
  );
};
