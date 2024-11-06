"use client";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";

export const AddProvider = () => {
  return (
    <div className="flex w-full items-center justify-end">
      <CustomButton
        asLink="/providers/connect-account"
        ariaLabel="Add Account"
        variant="solid"
        color="action"
        size="md"
        endContent={<AddIcon size={20} />}
      >
        Add Account
      </CustomButton>
    </div>
  );
};
