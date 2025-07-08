"use client";

import { SettingsIcon } from "lucide-react";

import { CustomLink } from "@/components/ui/custom";

export const ManageGroupsButton = () => {
  return (
    <CustomLink
      href={"/manage-groups"}
      ariaLabel="Manage Groups"
      variant="dashed"
      color="secondary"
      size="md"
      startContent={<SettingsIcon size={20} />}
    >
      Manage Groups
    </CustomLink>
  );
};
