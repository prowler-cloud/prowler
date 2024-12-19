"use client";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";

export const AddRoleButton = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomButton
        asLink="/roles/new"
        ariaLabel="Add Role"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Add Role
      </CustomButton>
    </div>
  );
};
