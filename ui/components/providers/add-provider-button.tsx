"use client";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";

export const AddProviderButton = () => {
  return (
    <CustomButton
      asLink="/providers/connect-account"
      ariaLabel="Add Cloud Provider"
      variant="solid"
      color="action"
      size="md"
      endContent={<AddIcon size={20} />}
    >
      Add Cloud Provider
    </CustomButton>
  );
};
