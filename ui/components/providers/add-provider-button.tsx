"use client";

import { CustomLink } from "@/components/ui/custom";

import { AddIcon } from "../icons";

export const AddProviderButton = () => {
  return (
    <CustomLink
      path="/providers/connect-account"
      ariaLabel="Add Cloud Provider"
      variant="solid"
      color="action"
      endContent={<AddIcon size={20} />}
    >
      Add Cloud Provider
    </CustomLink>
  );
};
