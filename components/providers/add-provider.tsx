"use client";

import { Chip } from "@nextui-org/react";
import { useState } from "react";

import { AddIcon } from "../icons";
import { CustomAlertModal, CustomButton } from "../ui/custom";
import { AddForm } from "./forms";

export const AddProvider = () => {
  const [isAddOpen, setIsAddOpen] = useState(false);

  return (
    <>
      <CustomAlertModal
        isOpen={isAddOpen}
        onOpenChange={setIsAddOpen}
        title="Add Cloud Provider"
        description={
          "You must manually deploy a new read-only IAM role for each account you want to add. The following links will provide detailed instructions how to do this:"
        }
      >
        <AddForm setIsOpen={setIsAddOpen} />
      </CustomAlertModal>

      <div className="w-full flex items-center justify-between">
        <div className="flex w-fit items-center gap-2">
          <h1 className="text-2xl font-[700] leading-[32px]">TBD</h1>
          <Chip
            className="hidden items-center text-default-500 sm:flex"
            size="sm"
            variant="flat"
          >
            3
          </Chip>
        </div>
        <CustomButton
          variant="solid"
          color="action"
          size="md"
          onPress={() => setIsAddOpen(true)}
          endContent={<AddIcon size={20} />}
        >
          Add Account
        </CustomButton>
      </div>
    </>
  );
};
