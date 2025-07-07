"use client";

import { SettingsIcon } from "lucide-react";

import { CustomLink } from "@/components/ui/custom";

export const ManageGroupsButton = () => {
  return (
    <CustomLink
      path={"/manage-groups"}
      ariaLabel="Manage Groups"
      variant="dashed"
      color="secondary"
      className="rounded-md px-4 py-2 !font-bold hover:border-solid hover:bg-default-100"
      startContent={<SettingsIcon size={20} />}
    >
      Manage Groups
    </CustomLink>
  );
};
