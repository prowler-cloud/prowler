"use client";

import { SettingsIcon } from "lucide-react";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { MutedFindingsConfigForm } from "./forms";

interface MutedFindingsConfigButtonProps {
  isDisabled?: boolean;
}

export const MutedFindingsConfigButton = ({
  isDisabled = false,
}: MutedFindingsConfigButtonProps) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleOpenModal = () => {
    if (!isDisabled) {
      setIsOpen(true);
    }
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        title="Configure Muted Findings"
        size="3xl"
      >
        <MutedFindingsConfigForm setIsOpen={setIsOpen} />
      </CustomAlertModal>

      <CustomButton
        ariaLabel="Configure Muted Findings"
        variant="dashed"
        color="warning"
        size="md"
        startContent={<SettingsIcon size={20} />}
        onPress={handleOpenModal}
        isDisabled={isDisabled}
      >
        Configure Muted Findings
      </CustomButton>
    </>
  );
};
