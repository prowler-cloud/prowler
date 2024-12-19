"use client";

import { SettingsIcon } from "lucide-react";

import { CustomButton } from "../ui/custom";

export const ManageGroupsButton = () => {
  return (
    <CustomButton
      asLink="/manage-groups"
      ariaLabel="Manage Groups"
      variant="dashed"
      color="warning"
      size="md"
      startContent={<SettingsIcon size={20} />}
    >
      Manage Groups
    </CustomButton>
  );
};
